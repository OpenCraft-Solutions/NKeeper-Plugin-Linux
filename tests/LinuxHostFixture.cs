using System.Security.Cryptography;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
using DotNet.Testcontainers.Containers;

namespace NKeeper.Plugins.Linux.Tests;

/// <summary>
/// An OpenSSH server made to look like a Linux host with a journal and SELinux: fake <c>journalctl</c>,
/// <c>getenforce</c>, <c>semodule</c>, <c>ausearch</c>, <c>audit2allow</c>, <c>checkmodule</c> and
/// <c>semodule_package</c>, answering in the real tools' formats (ported from 1.x's LinuxToolsServerFixture). Like the
/// real ones, those that read the system need root, which the (non-root) test user gets with sudo. A fake
/// <c>uname</c> can say the host is Windows.
/// </summary>
public sealed class LinuxHostFixture : IAsyncLifetime
{
    public const string UserName = "tester";
    public const string Password = "Linux-Test-Passw0rd";
    public const string Address = "127.0.0.1";
    public const int ContainerSshPort = 2222;

    private const UnixFileModes Executable = UnixFileModes.UserRead | UnixFileModes.UserWrite | UnixFileModes.UserExecute
        | UnixFileModes.GroupRead | UnixFileModes.GroupExecute | UnixFileModes.OtherRead | UnixFileModes.OtherExecute;

    private readonly IContainer _container = new ContainerBuilder("lscr.io/linuxserver/openssh-server:10.3_p1-r1-ls239")
        .WithHostname("linux-test")
        .WithEnvironment("PASSWORD_ACCESS", "true")
        .WithEnvironment("USER_NAME", UserName)
        .WithEnvironment("USER_PASSWORD", Password)
        .WithPortBinding(ContainerSshPort, assignRandomHostPort: true)
        .WithWaitStrategy(Wait.ForUnixContainer().UntilMessageIsLogged(@"\[ls\.io-init\] done\."))
        .Build();

    public int Port => _container.GetMappedPublicPort(ContainerSshPort);

    public async ValueTask InitializeAsync()
    {
        await _container.StartAsync();
        foreach (var tool in new[] { "journalctl", "getenforce", "semodule", "ausearch", "audit2allow", "checkmodule", "semodule_package", "uname" })
        {
            await _container.CopyAsync(
                await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory, "Linux", $"fake-{tool}.sh")), $"/usr/local/bin/{tool}", fileMode: Executable);
        }

        await ResetAsync();
    }

    /// <summary>Puts the journal, SELinux, the test user's sudo and its home folder back as they were.</summary>
    public async Task ResetAsync()
    {
        var setup = await _container.ExecAsync([
            "sh", "-c",
            "set -e; rm -rf /var/lib/fake-linux; mkdir -p /var/lib/fake-linux; chmod 777 /var/lib/fake-linux; cd /var/lib/fake-linux"
            + " && : > journal && : > journal-new && : > audit.log && : > journalctl-args && : > ausearch-args && chmod 666 journalctl-args ausearch-args"
            + " && echo Enforcing > mode && printf '100 base\\n100 httpd\\n400 my_old_fix\\n' > modules"
            + $" && echo '{UserName} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/nkeeper-test && chmod 440 /etc/sudoers.d/nkeeper-test"
            + " && rm -rf /config/files && mkdir -p /config/files && chown " + UserName + " /config/files",
        ]);
        if (setup.ExitCode != 0)
        {
            throw new InvalidOperationException($"Preparing the fake host failed: {setup.Stderr}");
        }
    }

    /// <summary>Runs a shell script on the host as root; returns what it printed.</summary>
    public async Task<string> ExecAsync(string script)
    {
        var result = await _container.ExecAsync(["sh", "-c", script]);
        return result.ExitCode == 0 ? result.Stdout : throw new InvalidOperationException($"{script} failed: {result.Stderr}");
    }

    /// <summary>Puts a file in the fake tools' folder.</summary>
    public Task WriteAsync(string name, string content) =>
        _container.CopyAsync(System.Text.Encoding.UTF8.GetBytes(content), $"/var/lib/fake-linux/{name}", fileMode: Executable);

    /// <summary>Reads a file from the fake tools' folder.</summary>
    public async Task<string> ReadAsync(string name) => (await _container.ExecAsync(["cat", $"/var/lib/fake-linux/{name}"])).Stdout;

    /// <summary>Takes away the test user's sudo, as on a host where it needs a password.</summary>
    public Task RemoveSudoAsync() => _container.ExecAsync(["rm", "-f", "/etc/sudoers.d/nkeeper-test"]);

    public ValueTask DisposeAsync() => _container.DisposeAsync();
}

/// <summary>
/// The released ssh plugin, whose <c>ssh</c> service type the tools open on: downloaded once, and checked against the
/// SHA-256 NKeeper's <c>deploy/plugins.lock</c> pins for it. It's signed with the official key, which the server trusts.
/// </summary>
public static class SshPluginRelease
{
    public const string Url = "https://github.com/OpenCraft-Solutions/NKeeper-Plugin-SSH/releases/download/v1.0.0/ssh-1.0.0.nkp";
    public const string Sha256 = "f8b43ee0181feba84f5281a55f3589676a8b8df78a1bc311c15777e30d63e113";

    private static readonly SemaphoreSlim Once = new(1, 1);

    public static async Task<string> PathAsync(CancellationToken cancellationToken)
    {
        var path = System.IO.Path.Combine(AppContext.BaseDirectory, "deps", "ssh-1.0.0.nkp");
        await Once.WaitAsync(cancellationToken);
        try
        {
            if (!File.Exists(path) || !Matches(await File.ReadAllBytesAsync(path, cancellationToken)))
            {
                using var http = new HttpClient();
                var bytes = await http.GetByteArrayAsync(new Uri(Url), cancellationToken);
                if (!Matches(bytes))
                {
                    throw new InvalidOperationException($"{Url} doesn't match the SHA-256 pinned for it.");
                }

                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
                await File.WriteAllBytesAsync(path, bytes, cancellationToken);
            }

            return path;
        }
        finally
        {
            Once.Release();
        }
    }

    private static bool Matches(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes)) == Sha256;
}
