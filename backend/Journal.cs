using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using NKeeper.Abstractions;

namespace NKeeper.Plugins.Linux;

/// <summary>One journal entry.</summary>
/// <param name="Cursor">Where it is in the journal, to read on from.</param>
/// <param name="Priority">syslog's: 0 (emergency) to 7 (debug); null when it has none.</param>
/// <param name="Unit">The systemd unit it came from.</param>
/// <param name="Identifier">The program's name for itself, e.g. <c>sshd</c>.</param>
public sealed record JournalEntry(string Cursor, DateTimeOffset? Time, int? Priority, string? Unit, string? Identifier, string? Pid, string? Hostname, string Message);

/// <summary>A page of entries, newest first.</summary>
/// <param name="HasMore">Older matching entries remain: ask with the last entry's cursor.</param>
/// <param name="Limited">The login could only read part of the journal: it isn't root and can't use sudo without a password.</param>
public sealed record JournalPage(IReadOnlyList<JournalEntry> Entries, bool HasMore, bool Limited);

/// <summary>What to read from the journal.</summary>
/// <param name="MaxPriority">This priority and worse.</param>
/// <param name="Search">A regular expression on the message (journalctl's <c>--grep</c>).</param>
/// <param name="After">Continue past this cursor, in the direction of reading.</param>
internal sealed record JournalQuery(DateTimeOffset? Since, DateTimeOffset? Until, int? MaxPriority, string? Unit, string? Identifier, string? Search, string? After)
{
    public static JournalQuery From(ToolRequest request)
    {
        var priority = request.Number("maxPriority");
        if (priority is < 0 or > 7)
        {
            throw new ToolException("The priority must be 0 (emergency) to 7 (debug).");
        }

        var after = request.Text("after", 512);
        if (!Journal.IsCursor(after))
        {
            throw new ToolException("That isn't a journal cursor.");
        }

        var (since, until) = (request.Time("since"), request.Time("until"));
        if (since > until)
        {
            throw new ToolException("The start is after the stop.");
        }

        return new JournalQuery(
            since,
            until,
            (int?)priority,
            request.Text("unit", 256),
            request.Text("identifier", 256),
            request.Text("search", 1024),
            after);
    }
}

/// <summary>A Linux host's systemd journal, read with <c>journalctl</c> over SSH. Ported from 1.x's <c>JournalHost</c>.</summary>
internal static partial class Journal
{
    public const int PageSize = 200;

    private const string Preamble = Shell.RootIfAllowed + "command -v journalctl >/dev/null 2>&1 || { echo 'This host has no journalctl (systemd).' >&2; exit 127; }; ";

    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(50);

    public static async Task<JournalPage> ReadAsync(ISshConnection ssh, JournalQuery query, CancellationToken cancellationToken)
    {
        var result = await Shell.RunAsync(ssh, ReadScript(query), Timeout, "Reading the journal", cancellationToken);
        var (text, limited) = Shell.WithoutLimitedMarker(result.Output);
        var message = result.Error.Trim();

        // With --grep, journalctl exits 1 when nothing matches, saying nothing.
        if (result.ExitStatus != 0 && message.Length > 0)
        {
            throw new ToolException(Explain(message));
        }

        var entries = text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(ParseEntry).OfType<JournalEntry>().ToList();
        var hasMore = entries.Count > PageSize;
        return new JournalPage(hasMore ? entries[..PageSize] : entries, hasMore, limited || message.Contains("not seeing messages", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Newest first, one more than a page to tell whether older entries remain.</summary>
    internal static string ReadScript(JournalQuery query) =>
        Preamble + "$p journalctl --no-pager --output=json --reverse " + string.Create(CultureInfo.InvariantCulture, $"--lines={PageSize + 1}") + Filters(query, includeTimes: true);

    /// <summary>From <paramref name="query"/>'s cursor (or from now) until stopped; a follow has no time limits.</summary>
    internal static string FollowScript(JournalQuery query) =>
        Preamble + "exec $p journalctl --no-pager --output=json --follow" + (query.After is null ? " --lines=0" : string.Empty) + Filters(query, includeTimes: false);

    private static string Filters(JournalQuery query, bool includeTimes)
    {
        var script = new StringBuilder();
        if (includeTimes && query.Since is { } since)
        {
            script.Append(CultureInfo.InvariantCulture, $" --since=@{since.ToUnixTimeSeconds()}");
        }

        if (includeTimes && query.Until is { } until)
        {
            script.Append(CultureInfo.InvariantCulture, $" --until=@{until.ToUnixTimeSeconds()}");
        }

        if (query.MaxPriority is { } priority)
        {
            script.Append(CultureInfo.InvariantCulture, $" --priority={priority}");
        }

        // Each value is one word after its option's "=", so it can't be taken for an option.
        Option(script, "unit", query.Unit);
        Option(script, "identifier", query.Identifier);
        Option(script, "grep", query.Search);
        Option(script, "after-cursor", query.After);
        return script.ToString();
    }

    private static void Option(StringBuilder script, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            script.Append(" --").Append(name).Append('=').Append(Shell.Quote(value.Trim()));
        }
    }

    public static bool IsCursor(string? value) => value is null || CursorFormat().IsMatch(value);

    /// <summary>What journalctl said, with what to do about the usual causes.</summary>
    internal static string Explain(string message)
    {
        if (message.Contains("grep", StringComparison.OrdinalIgnoreCase) && message.Contains("unrecognized option", StringComparison.OrdinalIgnoreCase))
        {
            return "This host's journalctl can't search messages (that needs systemd 237 or later). Leave Search empty, and use Find on the entries shown.";
        }

        if (message.Contains("insufficient permissions", StringComparison.OrdinalIgnoreCase))
        {
            return "This login can't read the journal. Use root, a user who may use sudo without a password, or one in the systemd-journal group.";
        }

        return message.StartsWith("Bad pattern", StringComparison.Ordinal) ? $"The search isn't a valid regular expression: {message}" : message;
    }

    /// <summary>One line of <c>journalctl --output=json</c>; null when it isn't an entry.</summary>
    internal static JournalEntry? ParseEntry(string line)
    {
        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || Field(root, "__CURSOR") is not { } cursor)
            {
                return null;
            }

            return new JournalEntry(
                cursor,
                long.TryParse(Field(root, "__REALTIME_TIMESTAMP"), NumberStyles.None, CultureInfo.InvariantCulture, out var micros) && micros / 1000 <= DateTimeOffset.MaxValue.ToUnixTimeMilliseconds()
                    ? DateTimeOffset.UnixEpoch.AddTicks(micros * TimeSpan.TicksPerMicrosecond)
                    : null,
                int.TryParse(Field(root, "PRIORITY"), NumberStyles.None, CultureInfo.InvariantCulture, out var priority) ? priority : null,
                Field(root, "_SYSTEMD_UNIT"),
                Field(root, "SYSLOG_IDENTIFIER") ?? Field(root, "_COMM"),
                Field(root, "_PID"),
                Field(root, "_HOSTNAME"),
                root.TryGetProperty("MESSAGE", out var message) && message.ValueKind == JsonValueKind.Null
                    ? "(This message is over 4 KB, so the journal doesn't send it. Read it on the host.)"
                    : AnsiCodes().Replace(Field(root, "MESSAGE") ?? string.Empty, string.Empty));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>A field: text, bytes when it isn't valid UTF-8 (an array of numbers), or the first of several values (an array).</summary>
    private static string? Field(JsonElement entry, string name)
    {
        if (!entry.TryGetProperty(name, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Array when value.GetArrayLength() > 0 && value[0].ValueKind == JsonValueKind.Number =>
                Encoding.UTF8.GetString([.. value.EnumerateArray().Where(b => b.ValueKind == JsonValueKind.Number && b.TryGetByte(out _)).Select(b => b.GetByte())]),
            JsonValueKind.Array when value.GetArrayLength() > 0 && value[0].ValueKind == JsonValueKind.String => value[0].GetString(),
            _ => null,
        };
    }

    [GeneratedRegex(@"^[A-Za-z0-9=;_-]{1,512}$")]
    private static partial Regex CursorFormat();

    [GeneratedRegex(@"\x1b\[[0-9;?]*[@-~]")]
    private static partial Regex AnsiCodes();
}

/// <summary>Opens the Journal tool: an SSH connection, checked to be Linux.</summary>
public sealed class JournalSessionHandler(IConnectivity connectivity, IPluginAudit audit) : IStreamSessionHandler
{
    public async Task<IStreamSession> OpenAsync(StreamSessionRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var ssh = await LinuxPlugin.OpenSshAsync(connectivity, request, "the journal", cancellationToken);
        try
        {
            return new JournalSession(ssh, audit, request.Host.Id, await Shell.NotLinuxAsync(ssh, "The journal", cancellationToken));
        }
        catch
        {
            await ssh.DisposeAsync();
            throw;
        }
    }
}

/// <summary>
/// The Journal tool (docs/architecture.md §7.25): <c>read</c> pages, newest first; <c>follow</c> streams new entries as
/// <c>entry</c> messages until <c>stop</c>, a new request, or the end of the session.
/// </summary>
internal sealed class JournalSession : ToolSession
{
    private readonly ISshConnection _ssh;
    private readonly IPluginAudit _audit;
    private readonly Guid _hostId;
    private bool _readAudited;
    private bool _followAudited;
    private ISshCommand? _follow;

    public JournalSession(ISshConnection ssh, IPluginAudit audit, Guid hostId, string? unsupported)
    {
        _ssh = ssh;
        _audit = audit;
        _hostId = hostId;
        Unsupported = unsupported;
    }

    protected override async Task HandleAsync(ToolRequest request, CancellationToken cancellationToken)
    {
        switch (request.Type)
        {
            case "read":
                {
                    await StopFollowAsync();
                    var page = await Journal.ReadAsync(_ssh, JournalQuery.From(request), cancellationToken);
                    if (!_readAudited)
                    {
                        _readAudited = true;
                        await _audit.RecordAsync("linux.journal-read", _hostId, page.Limited ? "limited to what the login may read" : "as root", cancellationToken);
                    }

                    await ReplyAsync(request.Id, page, cancellationToken);
                    break;
                }

            case "follow":
                {
                    await StopFollowAsync();
                    var query = JournalQuery.From(request);
                    var follow = await StartAsync(Journal.FollowScript(query), cancellationToken);
                    _follow = follow;
                    if (!_followAudited)
                    {
                        _followAudited = true;
                        await _audit.RecordAsync("linux.journal-follow", _hostId, "followed new entries", cancellationToken);
                    }

                    await ReplyAsync(request.Id, null, cancellationToken);
                    Background(request.Id, () => PumpAsync(request.Id, follow, cancellationToken), cancellationToken);
                    break;
                }

            case "stop":
                await StopFollowAsync();
                await ReplyAsync(request.Id, null, cancellationToken);
                break;

            default:
                throw new ToolException($"The journal doesn't know “{request.Type}”.");
        }
    }

    private async Task<ISshCommand> StartAsync(string script, CancellationToken cancellationToken)
    {
        try
        {
            return await _ssh.StartAsync(script, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new ConnectionLostException($"The SSH connection was lost: {ex.Message}");
        }
    }

    /// <summary>Sends each entry as it comes; when journalctl ends by itself, says why.</summary>
    private async Task PumpAsync(string id, ISshCommand follow, CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(follow.Output, Encoding.UTF8);
        var first = true;
        var limited = false;
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            if (first && line == "@@limited")
            {
                limited = true;
                await SendAsync(new { type = "limited", id }, cancellationToken);
            }
            else if (Journal.ParseEntry(line) is { } entry)
            {
                await SendAsync(new { type = "entry", id, entry }, cancellationToken);
            }

            first = false;
        }

        if (!ReferenceEquals(_follow, follow))
        {
            return;
        }

        var result = await follow.WaitAsync(cancellationToken);
        var message = result.Error.Trim();
        await SendAsync(new
        {
            type = "followEnded",
            id,
            message = message.Length > 0 ? Journal.Explain(message) : "journalctl stopped.",
            limited,
        }, cancellationToken);
    }

    private async Task StopFollowAsync()
    {
        if (_follow is { } follow)
        {
            _follow = null;
            await follow.DisposeAsync();
        }
    }

    protected override Task EndAsync() => StopFollowAsync();

    public override async ValueTask DisposeAsync()
    {
        await StopFollowAsync();
        await _ssh.DisposeAsync();
    }
}
