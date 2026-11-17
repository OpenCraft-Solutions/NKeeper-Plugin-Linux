using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading.Channels;
using NKeeper.Abstractions;

namespace NKeeper.Plugins.Linux;

/// <summary>Paths on the host, as 1.x's SftpController handled them.</summary>
internal static class RemotePath
{
    /// <summary>Absolute, without <c>.</c>, <c>..</c> or doubled slashes. A relative path is from <paramref name="home"/>.</summary>
    public static string Resolve(string home, string? path) =>
        Normalize(string.IsNullOrWhiteSpace(path) ? home : path.StartsWith('/') ? path : Join(home, path));

    public static string Normalize(string path)
    {
        var parts = new List<string>();
        foreach (var part in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == "..")
            {
                if (parts.Count > 0)
                {
                    parts.RemoveAt(parts.Count - 1);
                }
            }
            else if (part != ".")
            {
                parts.Add(part);
            }
        }

        return "/" + string.Join('/', parts);
    }

    public static string Join(string directory, string name) => Normalize($"{directory.TrimEnd('/')}/{name}");

    public static string? ParentOf(string path) => path == "/" ? null : Normalize(path + "/..");

    public static string NameOf(string path) => path == "/" ? "/" : path[(path.LastIndexOf('/') + 1)..];

    /// <summary>A name for a new file or folder: one path segment.</summary>
    public static string CheckName(string name) =>
        name.Length == 0 || name is "." or ".." || name.Contains('/', StringComparison.Ordinal) || name.Contains('\0', StringComparison.Ordinal)
            ? throw new ToolException("A name can't be empty, “.” or “..”, or contain “/”.")
            : name;
}

/// <summary>Opens the Files tool: an SFTP connection for the tab's life.</summary>
public sealed class FilesSessionHandler(IConnectivity connectivity, IPluginAudit audit, FileLinks links, Microsoft.AspNetCore.Http.IHttpContextAccessor http) : IStreamSessionHandler
{
    public async Task<IStreamSession> OpenAsync(StreamSessionRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Credential is null)
        {
            throw new ConnectException(ConnectFailure.NoSecret, "Choose a credential, or type one, to open the host's files.");
        }

        var userId = LinuxPlugin.UserId(http.HttpContext) ?? throw new InvalidOperationException("No signed-in user.");
        var sftp = await connectivity.OpenSftpAsync(request.Host, request.ServiceId, request.Credential, cancellationToken);
        return new FilesSession(sftp, audit, links, request.Host.Id, userId);
    }
}

/// <summary>
/// The Files tool (docs/architecture.md §7.25), ported from 1.x's SftpController: <c>list</c>, <c>sizes</c>,
/// <c>mkdir</c>, <c>delete</c>, <c>rename</c>, <c>upload</c> (then binary frames) and <c>download</c> (a one-time link).
/// </summary>
internal sealed class FilesSession(ISftpConnection sftp, IPluginAudit audit, FileLinks links, Guid hostId, Guid userId) : ToolSession
{
    public const long MaxUpload = 2L * 1024 * 1024 * 1024;
    public const int MaxChunk = 1024 * 1024;
    public const int WalkConcurrency = 16;
    public const int MaxSizePaths = 10_000;

    private static readonly HashSet<string> PseudoFileSystems = new(StringComparer.Ordinal) { "/proc", "/sys", "/dev" };

    private Upload? _upload;

    private sealed class Upload(string id, string path, long size, Stream stream)
    {
        public string Id { get; } = id;

        public string Path { get; } = path;

        public long Size { get; } = size;

        public Stream Stream { get; } = stream;

        public long Received { get; set; }
    }

    protected override async Task HandleAsync(ToolRequest request, CancellationToken cancellationToken)
    {
        if (_upload is not null && request.Type != "cancel")
        {
            throw new ToolException("Wait for the upload to finish, or cancel it.");
        }

        switch (request.Type)
        {
            case "list":
                {
                    var path = Resolve(request.Text("path", 4096));
                    var entries = (await sftp.ListAsync(path, cancellationToken))
                        .OrderBy(e => e.Kind == SftpEntryKind.Directory ? 0 : 1)
                        .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                        .ToList();
                    await ReplyAsync(request.Id, new { path, parent = RemotePath.ParentOf(path), entries }, cancellationToken);
                    break;
                }

            case "sizes":
                {
                    var paths = request.Array("paths", MaxSizePaths)
                        .Select(p => p.ValueKind == System.Text.Json.JsonValueKind.String && p.GetString() is { Length: > 0 and <= 4096 } text ? text : throw new ToolException("Each path must be text."))
                        .Distinct(StringComparer.Ordinal)
                        .ToList();
                    Background(request.Id, () => MeasureAsync(request.Id, paths, cancellationToken), cancellationToken);
                    break;
                }

            case "mkdir":
                {
                    var path = Resolve(request.RequiredText("path", 4096));
                    RemotePath.CheckName(RemotePath.NameOf(path));
                    await sftp.CreateDirectoryAsync(path, cancellationToken);
                    await audit.RecordAsync("linux.files-mkdir", hostId, path, cancellationToken);
                    await ReplyAsync(request.Id, new { path }, cancellationToken);
                    break;
                }

            case "delete":
                {
                    var path = Resolve(request.RequiredText("path", 4096));
                    var entry = await sftp.GetAsync(path, cancellationToken);
                    if (entry.Kind == SftpEntryKind.Directory)
                    {
                        if ((await sftp.ListAsync(path, cancellationToken)).Count > 0)
                        {
                            throw new ToolException($"{path} isn't empty. Delete what's in it first.");
                        }

                        await sftp.DeleteDirectoryAsync(path, cancellationToken);
                    }
                    else
                    {
                        await sftp.DeleteFileAsync(path, cancellationToken);
                    }

                    await audit.RecordAsync("linux.files-delete", hostId, path, cancellationToken);
                    await ReplyAsync(request.Id, new { path }, cancellationToken);
                    break;
                }

            case "rename":
                {
                    var path = Resolve(request.RequiredText("path", 4096));
                    var newName = request.RequiredText("newPath", 4096);
                    var target = newName.StartsWith('/') ? RemotePath.Normalize(newName) : RemotePath.Join(RemotePath.ParentOf(path) ?? "/", newName);
                    if (path == "/" || target == "/")
                    {
                        throw new ToolException("The root folder can't be renamed.");
                    }

                    await sftp.RenameAsync(path, target, cancellationToken);
                    await audit.RecordAsync("linux.files-rename", hostId, $"{path} to {target}", cancellationToken);
                    await ReplyAsync(request.Id, new { path = target }, cancellationToken);
                    break;
                }

            case "upload":
                await StartUploadAsync(request, cancellationToken);
                break;

            case "cancel":
                if (_upload is { } upload && upload.Id == request.RequiredText("upload", MaxIdLength))
                {
                    await AbortUploadAsync();
                    await ErrorAsync(upload.Id, "The upload was cancelled.", cancellationToken);
                }

                await ReplyAsync(request.Id, null, cancellationToken);
                break;

            case "download":
                {
                    var path = Resolve(request.RequiredText("path", 4096));
                    var entry = await sftp.GetAsync(path, cancellationToken);
                    if (entry.Kind is not (SftpEntryKind.File or SftpEntryKind.Directory))
                    {
                        throw new ToolException($"{path} isn't a file or a folder.");
                    }

                    var token = links.Create(new FileLink(userId, hostId, sftp, audit, entry, this));
                    await ReplyAsync(request.Id, new { url = $"/api/p/linux/hosts/{hostId}/files/{token}" }, cancellationToken);
                    break;
                }

            default:
                throw new ToolException($"Files doesn't know “{request.Type}”.");
        }
    }

    private string Resolve(string? path) => RemotePath.Resolve(sftp.HomeDirectory, path);

    private async Task StartUploadAsync(ToolRequest request, CancellationToken cancellationToken)
    {
        var folder = Resolve(request.RequiredText("path", 4096));
        var name = RemotePath.CheckName(request.RequiredText("name", 255));
        var size = request.Number("size") is { } value and >= 0 and <= MaxUpload ? value : throw new ToolException("A file can be at most 2 GB.");
        var path = RemotePath.Join(folder, name);
        var stream = await sftp.OpenWriteAsync(path, request.Flag("overwrite"), cancellationToken);
        _upload = new Upload(request.Id, path, size, stream);
        if (size == 0)
        {
            await FinishUploadAsync(_upload, cancellationToken);
            return;
        }

        await SendAsync(new { type = "ready", id = request.Id, path }, cancellationToken);
    }

    /// <summary>A chunk of the upload; each is acknowledged, so the browser sends no faster than the host takes it.</summary>
    protected override async Task BinaryAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        if (_upload is not { } upload)
        {
            return;
        }

        if (data.Length > MaxChunk || upload.Received + data.Length > upload.Size)
        {
            await AbortUploadAsync();
            await ErrorAsync(upload.Id, data.Length > MaxChunk ? "Each chunk can be at most 1 MB." : "More was sent than the file's size.", cancellationToken);
            return;
        }

        try
        {
            await upload.Stream.WriteAsync(data, cancellationToken);
        }
        catch (IOException ex)
        {
            await AbortUploadAsync();
            await ErrorAsync(upload.Id, ex.Message, cancellationToken);
            return;
        }

        upload.Received += data.Length;
        if (upload.Received == upload.Size)
        {
            await FinishUploadAsync(upload, cancellationToken);
        }
        else
        {
            await SendAsync(new { type = "ack", id = upload.Id, received = upload.Received }, cancellationToken);
        }
    }

    private async Task FinishUploadAsync(Upload upload, CancellationToken cancellationToken)
    {
        _upload = null;
        try
        {
            await upload.Stream.DisposeAsync();
        }
        catch (IOException ex)
        {
            await DeleteQuietlyAsync(upload.Path);
            await ErrorAsync(upload.Id, ex.Message, cancellationToken);
            return;
        }

        await audit.RecordAsync("linux.files-upload", hostId, $"{upload.Path} ({upload.Size:N0} bytes)", cancellationToken);
        await ReplyAsync(upload.Id, new { path = upload.Path }, cancellationToken);
    }

    /// <summary>Stops an upload and deletes what it wrote: a part of a file is no use.</summary>
    private async Task AbortUploadAsync()
    {
        if (_upload is not { } upload)
        {
            return;
        }

        _upload = null;
        try
        {
            await upload.Stream.DisposeAsync();
        }
        catch (IOException)
        {
        }

        await DeleteQuietlyAsync(upload.Path);
    }

    private async Task DeleteQuietlyAsync(string path)
    {
        try
        {
            await sftp.DeleteFileAsync(path, CancellationToken.None);
        }
        catch (SftpException)
        {
        }
    }

    protected override async Task EndAsync()
    {
        links.Revoke(this);
        await AbortUploadAsync();
    }

    public override async ValueTask DisposeAsync()
    {
        links.Revoke(this);
        await sftp.DisposeAsync();
    }

    /// <summary>
    /// The bytes in the files below some folders, each sent as <c>size</c> as soon as it's known, then a reply. All the
    /// folders share one queue, oldest first, so a huge one can't hold up the rest. Ported from 1.x.
    /// </summary>
    private async Task MeasureAsync(string id, List<string> paths, CancellationToken cancellationToken)
    {
        if (paths.Count == 0)
        {
            await ReplyAsync(id, null, cancellationToken);
            return;
        }

        var work = Channel.CreateUnbounded<(FolderTotal Total, string Folder)>();
        var outstanding = paths.Count;
        foreach (var path in paths)
        {
            work.Writer.TryWrite((new FolderTotal(path), Resolve(path)));
        }

        var options = new ParallelOptions { MaxDegreeOfParallelism = WalkConcurrency, CancellationToken = cancellationToken };
        await Parallel.ForEachAsync(work.Reader.ReadAllAsync(cancellationToken), options, async (item, token) =>
        {
            var total = item.Total;
            var files = await ReadFolderAsync(item.Folder, token);
            if (files is null)
            {
                total.Complete = false;
            }

            var size = 0L;
            foreach (var file in files ?? [])
            {
                if (file.Kind == SftpEntryKind.Directory)
                {
                    Interlocked.Increment(ref total.Pending);
                    Interlocked.Increment(ref outstanding);
                    work.Writer.TryWrite((total, file.Path));
                }
                else if (file.Kind == SftpEntryKind.File)
                {
                    size += file.Size;
                }
            }

            Interlocked.Add(ref total.Size, size);
            if (Interlocked.Decrement(ref total.Pending) == 0)
            {
                await SendAsync(new { type = "size", id, path = total.Path, size = Volatile.Read(ref total.Size), complete = total.Complete }, token);
            }

            if (Interlocked.Decrement(ref outstanding) == 0)
            {
                work.Writer.TryComplete();
            }
        });
        await ReplyAsync(id, null, cancellationToken);
    }

    /// <summary>What's in a folder, or null if it can't be read or isn't real files. A lost connection still throws.</summary>
    private async Task<IReadOnlyList<SftpEntry>?> ReadFolderAsync(string folder, CancellationToken cancellationToken)
    {
        if (PseudoFileSystems.Contains(folder))
        {
            return null;
        }

        try
        {
            return await sftp.ListAsync(folder, cancellationToken);
        }
        catch (SftpException ex) when (ex.Reason != SftpFailure.ConnectionLost)
        {
            return null;
        }
    }

    private sealed class FolderTotal(string path)
    {
        public string Path { get; } = path;

        public long Size;

        /// <summary>Folders still to read; starts with the folder itself.</summary>
        public int Pending = 1;

        public volatile bool Complete = true;
    }
}

/// <summary>What a download link gives: an entry, through the session's open connection, to one user on one host.</summary>
internal sealed record FileLink(Guid UserId, Guid HostId, ISftpConnection Sftp, IPluginAudit Audit, SftpEntry Entry, FilesSession Session);

/// <summary>
/// One-time download links (docs/architecture.md §7.25): for a minute, for the user and host that asked, while their
/// Files session is open. Ported from 1.x's <c>SftpDownloadLinks</c>.
/// </summary>
public sealed class FileLinks(TimeProvider time)
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<string, (FileLink Link, DateTimeOffset Expires)> _links = new(StringComparer.Ordinal);

    internal string Create(FileLink link)
    {
        var now = time.GetUtcNow();
        foreach (var expired in _links.Where(l => l.Value.Expires < now).Select(l => l.Key).ToList())
        {
            _links.TryRemove(expired, out _);
        }

        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24));
        _links[token] = (link, now + Lifetime);
        return token;
    }

    internal FileLink? Take(string token, Guid userId, Guid hostId) =>
        _links.TryRemove(token, out var entry) && entry.Link.UserId == userId && entry.Link.HostId == hostId && entry.Expires >= time.GetUtcNow()
            ? entry.Link
            : null;

    /// <summary>The session ended: its links go with it.</summary>
    internal void Revoke(FilesSession session)
    {
        foreach (var key in _links.Where(l => ReferenceEquals(l.Value.Link.Session, session)).Select(l => l.Key).ToList())
        {
            _links.TryRemove(key, out _);
        }
    }
}
