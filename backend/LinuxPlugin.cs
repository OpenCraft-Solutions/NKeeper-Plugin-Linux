using System.IO.Compression;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Net.Http.Headers;
using NKeeper.Abstractions;

namespace NKeeper.Plugins.Linux;

/// <summary>
/// The linux plugin (docs/architecture.md §7.25): Files, Journal, SELinux and the internal scan on the ssh plugin's <c>ssh</c> services.
/// Core opens the connections, checks the server's key and signs in; this plugin only runs the tools.
/// </summary>
public sealed class LinuxPlugin : IPlugin
{
    /// <summary>The ssh plugin's service type, which the tools open on.</summary>
    public const string SshServiceType = "ssh";

    public void Contribute(IPluginContributions contributions, PluginContext context)
    {
        contributions.AddSessionType(new SessionType("linux-files", "Files", typeof(FilesSessionHandler)) { ServiceTypes = [SshServiceType] });
        contributions.AddSessionType(new SessionType("linux-journal", "Journal", typeof(JournalSessionHandler)) { ServiceTypes = [SshServiceType] });
        contributions.AddSessionType(new SessionType("linux-selinux", "SELinux", typeof(SelinuxSessionHandler)) { ServiceTypes = [SshServiceType] });
        contributions.AddHostAction(new HostAction("linux.files", "Files", SessionType: "linux-files"));
        contributions.AddHostAction(new HostAction("linux.journal", "Journal", SessionType: "linux-journal"));
        contributions.AddHostAction(new HostAction("linux.selinux", "SELinux", SessionType: "linux-selinux"));
        contributions.AddHostAction(new HostAction("linux.scan", "Linux (internal)") { Endpoint = "scan", ServiceTypes = [SshServiceType], Scan = true });
    }

    public void ConfigureServices(IServiceCollection services, PluginContext context)
    {
        services.AddHttpContextAccessor();
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<FileLinks>();
        services.AddScoped<FilesSessionHandler>();
        services.AddScoped<JournalSessionHandler>();
        services.AddScoped<SelinuxSessionHandler>();
    }

    public void MapEndpoints(IEndpointRouteBuilder endpoints, PluginContext context)
    {
        var use = endpoints.MapHostGroup(HostPermission.Use);
        use.MapGet("/files/{token}", DownloadAsync);

        // Only someone who can change the host applies what a scan finds (§7.26).
        endpoints.MapHostGroup(HostPermission.Manage).MapPost("/scan", Scanner.ScanAsync);
    }

    internal static Guid? UserId(HttpContext? context) =>
        Guid.TryParse(context?.User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;

    /// <summary>Opens the SSH connection a script tool needs. Core reports the failures.</summary>
    internal static async Task<ISshConnection> OpenSshAsync(IConnectivity connectivity, StreamSessionRequest request, string what, CancellationToken cancellationToken) =>
        request.Credential is { } credential
            ? await connectivity.OpenSshAsync(request.Host, request.ServiceId, credential, cancellationToken)
            : throw new ConnectException(ConnectFailure.NoSecret, $"Choose a credential, or type one, to open {what}.");

    /// <summary>A one-time download link (§7.25): a file streamed as it is read, or a folder as a zip written as it streams.</summary>
    private static async Task<IResult> DownloadAsync(HostContext host, string token, HttpContext context, FileLinks links)
    {
        if (UserId(context) is not { } userId || links.Take(token, userId, host.Id) is not { } link)
        {
            return Results.Problem(statusCode: StatusCodes.Status404NotFound, detail: "This download link has expired or was already used. Download it again.");
        }

        var cancellationToken = context.RequestAborted;
        var entry = link.Entry;
        context.Response.Headers.CacheControl = "no-store";
        if (entry.Kind == SftpEntryKind.Directory)
        {
            var name = entry.Path == "/" ? "root" : entry.Name;
            await link.Audit.RecordAsync("linux.files-download", host.Id, $"{entry.Path} (folder)", cancellationToken);
            context.Response.ContentType = "application/zip";
            context.Response.Headers.ContentDisposition = Disposition(name + ".zip");
            // ZipArchive still writes some of its records synchronously, which the response doesn't allow; through a
            // pipe, those writes wait for the pipe, and the response is written asynchronously as it drains.
            var pipe = new System.IO.Pipelines.Pipe();
            var sending = pipe.Reader.CopyToAsync(context.Response.Body, cancellationToken);
            try
            {
                await using var zipped = pipe.Writer.AsStream(leaveOpen: true);
                await WriteZipAsync(link.Sftp, entry.Path, zipped, cancellationToken);
            }
            finally
            {
                await pipe.Writer.CompleteAsync();
            }

            await sending;
            return Results.Empty;
        }

        Stream source;
        try
        {
            source = await link.Sftp.OpenReadAsync(entry.Path, cancellationToken);
        }
        catch (SftpException ex)
        {
            return Results.Problem(statusCode: StatusCodes.Status409Conflict, detail: ex.Message);
        }

        await using (source)
        {
            await link.Audit.RecordAsync("linux.files-download", host.Id, $"{entry.Path} ({entry.Size:N0} bytes)", cancellationToken);
            context.Response.ContentType = "application/octet-stream";
            context.Response.ContentLength = entry.Size;
            context.Response.Headers.ContentDisposition = Disposition(entry.Name);
            await source.CopyToAsync(context.Response.Body, cancellationToken);
        }

        return Results.Empty;
    }

    private static string Disposition(string fileName)
    {
        var header = new ContentDispositionHeaderValue("attachment");
        header.SetHttpFileName(fileName);
        return header.ToString();
    }

    /// <summary>
    /// Zips everything below a folder, straight to the response. What can't be read is left out, and listed in a file in
    /// the zip so it's not silently missing. Ported from 1.x, which built the zip in a temporary file first.
    /// </summary>
    internal static async Task WriteZipAsync(ISftpConnection sftp, string root, Stream output, CancellationToken cancellationToken)
    {
        var skipped = new List<string>();
        await using var zip = await ZipArchive.CreateAsync(output, ZipArchiveMode.Create, leaveOpen: true, entryNameEncoding: null, cancellationToken);
        var folders = new Stack<string>([root]);
        while (folders.TryPop(out var folder))
        {
            IReadOnlyList<SftpEntry> files;
            try
            {
                files = folder is "/proc" or "/sys" or "/dev" ? throw new SftpException(SftpFailure.Failed, folder) : await sftp.ListAsync(folder, cancellationToken);
            }
            catch (SftpException ex) when (ex.Reason != SftpFailure.ConnectionLost)
            {
                skipped.Add(folder);
                continue;
            }

            if (files.Count == 0 && folder != root)
            {
                zip.CreateEntry($"{ZipName(root, folder)}/");
            }

            foreach (var file in files)
            {
                if (file.Kind == SftpEntryKind.Directory)
                {
                    folders.Push(file.Path);
                }
                else if (file.Kind == SftpEntryKind.File)
                {
                    try
                    {
                        await using var source = await sftp.OpenReadAsync(file.Path, cancellationToken);
                        var entry = zip.CreateEntry(ZipName(root, file.Path), CompressionLevel.Fastest);

                        // A zip can't hold dates outside these years, and old timestamps do turn up.
                        if (file.ModifiedUtc.Year is >= 1980 and <= 2107)
                        {
                            entry.LastWriteTime = file.ModifiedUtc;
                        }

                        await using var target = await entry.OpenAsync(cancellationToken);
                        await source.CopyToAsync(target, cancellationToken);
                    }
                    catch (SftpException ex) when (ex.Reason != SftpFailure.ConnectionLost)
                    {
                        skipped.Add(file.Path);
                    }
                }
            }
        }

        if (skipped.Count > 0)
        {
            var note = new StringBuilder($"These couldn't be read from {root}, so they are missing or incomplete in this zip:\n");
            foreach (var path in skipped)
            {
                note.Append(path).Append('\n');
            }

            await using var target = await zip.CreateEntry("_nkeeper-unreadable.txt").OpenAsync(cancellationToken);
            await target.WriteAsync(Encoding.UTF8.GetBytes(note.ToString()), cancellationToken);
        }
    }

    /// <summary>The path inside the zip. A backslash is legal in a name here but a separator to some unzip tools, which could climb out of the folder.</summary>
    private static string ZipName(string root, string path) => path[(root.TrimEnd('/').Length + 1)..].Replace('\\', '_');
}
