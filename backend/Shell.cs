using NKeeper.Abstractions;

namespace NKeeper.Plugins.Linux;

/// <summary>Running the tools' shell scripts on a Linux host. Ported from 1.x's <c>SshScript</c>.</summary>
internal static class Shell
{
    /// <summary>
    /// Sets up the tools' usual folders and <c>$p</c>: <c>sudo -n</c> when it's needed and allowed; nothing otherwise,
    /// leaving what the login may do itself, after an <c>@@limited</c> line.
    /// </summary>
    public const string RootIfAllowed =
        "PATH=$PATH:/usr/sbin:/sbin; p=''; if [ \"$(id -u)\" != 0 ]; then if sudo -n true 2>/dev/null; then p='sudo -n'; else echo '@@limited'; fi; fi; ";

    /// <summary>A single shell word, whatever it holds.</summary>
    public static string Quote(string value) => "'" + value.Replace("'", "'\\''", StringComparison.Ordinal) + "'";

    /// <summary>The text after the <c>@@limited</c> line, and whether it was there.</summary>
    public static (string Output, bool Limited) WithoutLimitedMarker(string output)
    {
        const string marker = "@@limited\n";
        return output.StartsWith(marker, StringComparison.Ordinal) ? (output[marker.Length..], true) : (output, false);
    }

    /// <summary>Runs a script; a timeout says <paramref name="what"/> didn't finish, and a lost connection ends the tool.</summary>
    public static async Task<SshCommandResult> RunAsync(ISshConnection ssh, string script, TimeSpan timeout, string what, CancellationToken cancellationToken)
    {
        try
        {
            return await ssh.RunAsync(script, timeout, cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new ToolException($"{what} didn't finish in time.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not ToolException)
        {
            throw new ConnectionLostException($"The SSH connection was lost: {ex.Message}");
        }
    }

    /// <summary>
    /// Why a Linux tool can't be used on this host, or null when it can. An SSH service may be Windows' OpenSSH, or a
    /// switch's, where the tools' scripts mean nothing (docs/architecture.md §7.25).
    /// </summary>
    public static async Task<string?> NotLinuxAsync(ISshConnection ssh, string tool, CancellationToken cancellationToken)
    {
        var result = await ssh.RunAsync("uname -s", TimeSpan.FromSeconds(20), cancellationToken);
        var system = result.Output.Trim();
        if (result.ExitStatus == 0 && system == "Linux")
        {
            return null;
        }

        var said = system.Length is > 0 and <= 40 && result.ExitStatus == 0 ? $" (it says it's {system})" : string.Empty;
        return $"{tool} is for Linux hosts, and this one isn't Linux{said}.";
    }
}
