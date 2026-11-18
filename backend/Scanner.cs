using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using NKeeper.Abstractions;

namespace NKeeper.Plugins.Linux;

/// <summary>
/// The Linux internal scan (docs/architecture.md §7.25, §7.26), ported from 1.x's <c>InternalScan</c>: one SSH login
/// runs one read-only script that reads the host's own state. Nothing on the network is probed, so on the wire it's
/// just an SSH login, like any admin's. A hypervisor's guests, Proxmox clusters, SQL Server and Oracle wait for their
/// own plugins.
/// </summary>
internal static partial class Scanner
{
    private const string End = "end";
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    /// <summary>The most neighbour entries recorded, so a host with a huge table can't flood the findings.</summary>
    internal const int MaxNeighbors = 512;

    /// <summary>
    /// Each section starts with a "@@name" line. Every command is a local query: `ip route show` reads the routing
    /// table, `ss`/`netstat` list sockets, `ip neigh` the existing neighbour table, and nothing probes other machines.
    /// </summary>
    internal const string Script = """
        s() { printf '\n@@%s\n' "$1"; }
        s hostname; hostname -f 2>/dev/null || hostname 2>/dev/null || uname -n
        s os
        if [ -r /etc/os-release ]; then (. /etc/os-release; echo "${PRETTY_NAME:-$NAME $VERSION}"); fi
        s kernel; uname -srm 2>/dev/null
        s connection; echo "$SSH_CONNECTION"
        s addresses; ip -o addr show 2>/dev/null
        s macs; for i in /sys/class/net/*; do [ -r "$i/address" ] && printf '%s %s\n' "${i##*/}" "$(cat "$i/address")"; done 2>/dev/null
        s route; ip route show default 2>/dev/null
        s listening; ss -Hltn 2>/dev/null || netstat -ltn 2>/dev/null
        s uidmin; sed -n 's/^UID_MIN[[:space:]]*//p' /etc/login.defs 2>/dev/null
        s users; getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null
        s virt; systemd-detect-virt 2>/dev/null
        s cpus; nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null
        s memory
        # Installed memory (lsmem) is closer to what the hardware has than the kernel's MemTotal.
        printf 'online %s\n' "$(lsmem -b --summary=only 2>/dev/null | sed -n 's/^Total online memory:[[:space:]]*//p')"
        sed -n 's/^MemTotal:[[:space:]]*\([0-9]*\).*/memtotal \1/p' /proc/meminfo 2>/dev/null
        s serial
        # Only root may read it on most systems; sudo is tried only where it needs no password.
        f=/sys/class/dmi/id/product_serial
        if [ -r "$f" ]; then cat "$f"; elif [ -e "$f" ]; then sudo -n cat "$f" 2>/dev/null || echo '(unreadable)'; fi
        s neighbors
        ip neigh show 2>/dev/null || arp -an 2>/dev/null
        s end
        """;

    private static readonly string[] NoLoginShells = ["nologin", "false", "sync", "shutdown", "halt"];

    /// <summary>Placeholders firmware ships when no serial number was set.</summary>
    private static readonly string[] SerialPlaceholders =
        ["to be filled by o.e.m.", "default string", "system serial number", "not specified", "not applicable", "none", "n/a", "0123456789", "chassis serial number"];

    private static readonly char[] Whitespace = [' ', '\t'];

    /// <summary>The scan action's endpoint (§7.26): Manage, since only someone who can change the host applies what it finds.</summary>
    internal static async Task<IResult> ScanAsync(HostContext host, ScanRequest request, ICredentialBroker broker, IConnectivity connectivity, IPluginAudit audit, CancellationToken cancellationToken)
    {
        if (host.Services.FirstOrDefault(s => s.Id == request.ServiceId) is not { Type: LinuxPlugin.SshServiceType })
        {
            return Problem(StatusCodes.Status400BadRequest, "bad_request", "This host has no such SSH service. Reload the host and try again.");
        }

        CredentialHandle handle;
        try
        {
            handle = request.CredentialId is { } credentialId
                ? await broker.ResolveSavedAsync(host, request.ServiceId, credentialId, cancellationToken)
                : request.PromptReference is { Length: > 0 } reference
                    ? await broker.ResolvePromptAsync(host, request.ServiceId, reference, cancellationToken)
                    : throw new ConnectException(ConnectFailure.NoSecret, "Choose a credential, or type one, to scan the host.");
        }
        catch (CredentialDeniedException ex)
        {
            return Problem(StatusCodes.Status403Forbidden, "credential_denied", ex.Message);
        }
        catch (ConnectException ex)
        {
            return Problem(StatusCodes.Status400BadRequest, "no_secret", ex.Message);
        }

        try
        {
            await using var ssh = await connectivity.OpenSshAsync(host, request.ServiceId, handle, cancellationToken);
            if (await Shell.NotLinuxAsync(ssh, "The Linux scan", cancellationToken) is { } notLinux)
            {
                return Problem(StatusCodes.Status409Conflict, "not_linux", notLinux);
            }

            SshCommandResult result;
            try
            {
                // Run with sh whatever the login shell is (bash, zsh, fish...).
                result = await ssh.RunAsync($"sh -c {Shell.Quote(Script)}", Timeout, cancellationToken);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return Problem(StatusCodes.Status504GatewayTimeout, "timeout", "The host didn't finish the scan in time.");
            }

            if (Parse(result.Output) is not { } findings)
            {
                return Problem(StatusCodes.Status409Conflict, "not_linux", "The host didn't run the scan: it needs a POSIX shell (sh).");
            }

            await audit.RecordAsync("linux.scan", host.Id, $"service {request.ServiceId}: {findings.Ports.Count} ports, {findings.Users.Count} accounts, {findings.Neighbors.Count} neighbours", cancellationToken);
            return Results.Ok(findings);
        }
        catch (ConnectException ex)
        {
            return ex.Presented is { } presented
                ? Problem(StatusCodes.Status409Conflict, "host_key_unknown", ex.Message, presented)
                : Problem(StatusCodes.Status502BadGateway, Code(ex.Reason), ex.Message);
        }
        catch (CredentialDeniedException ex)
        {
            return Problem(StatusCodes.Status403Forbidden, "credential_denied", ex.Message);
        }
    }

    /// <summary>Turns the script's output into findings; null when the script didn't run to its end.</summary>
    internal static ScanFindings? Parse(string output)
    {
        var sections = Sections(output);
        if (!sections.ContainsKey(End))
        {
            return null;
        }

        var notes = new List<string>();
        var hostname = First(sections, "hostname") is { } name && name != "localhost" && !name.Contains(' ', StringComparison.Ordinal) ? name : null;

        // SSH_CONNECTION is "client_ip client_port server_ip server_port": the address NKeeper reached.
        var connection = First(sections, "connection")?.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var serverIp = connection is { Length: 4 } ? NormalizeIp(connection[2]) : null;
        var clientIp = connection is { Length: 4 } ? NormalizeIp(connection[0]) : null;

        var ports = new SortedSet<int>();
        foreach (var line in Lines(sections, "listening"))
        {
            // ss -Hltn and netstat -ltn both have the local address:port as the fourth column.
            var columns = line.Split(Whitespace, StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length >= 4 && SplitEndpoint(columns[3]) is var (address, port) && !IsLoopback(address))
            {
                ports.Add(port);
            }
        }

        if (Lines(sections, "listening").Count == 0)
        {
            notes.Add("The listening ports couldn't be read (neither ss nor netstat is available).");
        }

        var virtualization = First(sections, "virt") is { } virt && virt != "none" ? virt : null;
        return new ScanFindings
        {
            Hostname = hostname,
            IpAddress = serverIp,
            MacAddress = FindMac(sections, serverIp, notes),
            OperatingSystem = First(sections, "os") ?? First(sections, "kernel"),
            CpuCores = PositiveInt(First(sections, "cpus")),
            MemoryMiB = MemoryMiB(sections),

            // A VM's "serial number" is made up by its hypervisor: only hardware's is worth recording.
            SerialNumber = virtualization is null ? Serial(First(sections, "serial"), notes) : null,
            Virtualization = virtualization,
            Ports = [.. ports.Select(Describe)],
            Users = Users(sections),
            Neighbors = Neighbors(sections, OwnAddresses(sections, serverIp, clientIp), notes),
            Notes = notes,
        };
    }

    /// <summary>A well-known name for a port, and the official plugins' service type it is, where it's one of theirs.</summary>
    internal static ScannedPort Describe(int port)
    {
        var (name, type) = port switch
        {
            22 => ("SSH", "ssh"),
            23 => ("Telnet", "telnet"),
            80 => ("HTTP", "http"),
            8080 or 8000 or 8008 or 8081 or 8888 => ("HTTP (alternate)", "http"),
            443 => ("HTTPS", "https"),
            8443 => ("HTTPS (alternate)", "https"),
            9090 => ("Cockpit", "https"),
            8006 => ("Proxmox VE", "https"),
            10000 => ("Webmin", "https"),
            3389 => ("Remote Desktop (RDP)", "rdp"),
            >= 5900 and <= 5909 => ($"VNC (display :{port - 5900})", "vnc"),
            _ => (Names.GetValueOrDefault(port), null),
        };
        return new ScannedPort(port, name, type);
    }

    private static readonly Dictionary<int, string> Names = new()
    {
        [21] = "FTP",
        [25] = "SMTP",
        [53] = "DNS",
        [88] = "Kerberos",
        [110] = "POP3",
        [111] = "RPC portmapper",
        [139] = "NetBIOS",
        [143] = "IMAP",
        [389] = "LDAP",
        [445] = "SMB (file sharing)",
        [465] = "SMTP (TLS)",
        [587] = "SMTP (submission)",
        [631] = "Printer (IPP)",
        [636] = "LDAPS",
        [873] = "rsync",
        [993] = "IMAPS",
        [995] = "POP3S",
        [1433] = "SQL Server",
        [1521] = "Oracle",
        [1883] = "MQTT",
        [2049] = "NFS",
        [2375] = "Docker API",
        [2376] = "Docker API (TLS)",
        [3000] = "HTTP (app, e.g. Grafana)",
        [3306] = "MySQL / MariaDB",
        [5432] = "PostgreSQL",
        [5672] = "AMQP (RabbitMQ)",
        [6379] = "Redis",
        [6443] = "Kubernetes API",
        [9100] = "Node exporter",
        [9200] = "Elasticsearch",
        [10050] = "Zabbix agent",
        [11211] = "Memcached",
        [16509] = "libvirt",
        [27017] = "MongoDB",
    };

    /// <summary>The accounts that can log in: root, and regular users (from UID_MIN), with a real shell.</summary>
    private static List<ScannedUser> Users(Dictionary<string, List<string>> sections)
    {
        var uidMin = int.TryParse(First(sections, "uidmin"), CultureInfo.InvariantCulture, out var min) ? min : 1000;
        var users = new List<ScannedUser>();
        foreach (var line in Lines(sections, "users"))
        {
            var fields = line.Split(':');
            if (fields.Length < 7 || !int.TryParse(fields[2], CultureInfo.InvariantCulture, out var uid))
            {
                continue;
            }

            var shell = fields[6];
            var canLogIn = !NoLoginShells.Any(s => shell.EndsWith(s, StringComparison.Ordinal));
            if (canLogIn && fields[0].Length > 0 && (uid == 0 || (uid >= uidMin && uid != 65534)) && !users.Any(u => u.Username == fields[0]))
            {
                var fullName = fields[4].Split(',')[0].Trim();
                users.Add(new ScannedUser(fields[0], fullName.Length > 0 ? fullName : null));
            }
        }

        return users;
    }

    /// <summary>Installed memory (lsmem, bytes), else the kernel's MemTotal (KiB), in MiB.</summary>
    private static int? MemoryMiB(Dictionary<string, List<string>> sections)
    {
        long? Value(string key) =>
            Lines(sections, "memory").Select(l => l.Split(' ', 2)).FirstOrDefault(f => f[0] == key && f.Length == 2) is { } found
            && long.TryParse(found[1].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var value) && value > 0 ? value : null;
        var mib = Value("online") is { } online ? online / (1024 * 1024) : Value("memtotal") is { } kib ? kib / 1024 : (long?)null;
        return mib is > 0 and <= int.MaxValue ? (int)mib : null;
    }

    /// <summary>A real serial number, or null for empty values and firmware placeholders.</summary>
    internal static string? Serial(string? value, List<string>? notes = null)
    {
        if (value == "(unreadable)")
        {
            notes?.Add("The serial number can only be read as root: scan as root, or as a user with passwordless sudo, to record it.");
            return null;
        }

        var serial = value?.Trim();
        return string.IsNullOrEmpty(serial) || serial.Length > 100 || serial.All(c => c is '0' or ' ' or '.' or '-')
            || SerialPlaceholders.Contains(serial, StringComparer.OrdinalIgnoreCase)
            ? null
            : serial;
    }

    private static int? PositiveInt(string? value) =>
        int.TryParse(value?.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var number) && number > 0 ? number : null;

    /// <summary>
    /// The host's own addresses, which aren't neighbours: every address on its interfaces, plus both ends of the SSH
    /// connection (NKeeper's own address is always in the host's table).
    /// </summary>
    private static HashSet<string> OwnAddresses(Dictionary<string, List<string>> sections, string? serverIp, string? clientIp)
    {
        var own = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var address in new[] { serverIp, clientIp })
        {
            if (address is not null)
            {
                own.Add(address);
            }
        }

        // "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0 ..." (inet6 for IPv6).
        foreach (var line in Lines(sections, "addresses"))
        {
            var columns = line.Split(Whitespace, StringSplitOptions.RemoveEmptyEntries);
            var index = Array.FindIndex(columns, c => c is "inet" or "inet6");
            if (index >= 0 && index + 1 < columns.Length && NormalizeIp(columns[index + 1].Split('/')[0]) is { } ip)
            {
                own.Add(ip);
            }
        }

        return own;
    }

    /// <summary>Complete entries with a real MAC address, one per address, without the host's own.</summary>
    private static List<ScannedNeighbor> Neighbors(Dictionary<string, List<string>> sections, HashSet<string> own, List<string> notes)
    {
        var neighbors = new List<ScannedNeighbor>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in Lines(sections, "neighbors"))
        {
            var (ip, mac) = ParseNeighborLine(line);
            if (ip is null || mac is null || own.Contains(ip) || !seen.Add(ip))
            {
                continue;
            }

            if (neighbors.Count >= MaxNeighbors)
            {
                notes.Add($"The neighbour table had more than {MaxNeighbors} entries; only the first {MaxNeighbors} were read.");
                break;
            }

            neighbors.Add(new ScannedNeighbor(ip, mac));
        }

        return neighbors;
    }

    /// <summary>
    /// One neighbour line, from `ip neigh show` ("IP dev IF lladdr MAC STATE") or `arp -an` ("? (IP) at MAC [ether] on
    /// IF"), as (IP, MAC). Null for an incomplete or failed lookup, loopback, link-local, multicast or broadcast.
    /// </summary>
    internal static (string? Ip, string? Mac) ParseNeighborLine(string line)
    {
        var tokens = line.Split(Whitespace, StringSplitOptions.RemoveEmptyEntries);
        string? rawMac = null;
        for (var i = 0; i + 1 < tokens.Length; i++)
        {
            if (tokens[i] is "lladdr" or "at")
            {
                rawMac = tokens[i + 1];
            }
        }

        var parenthesized = Array.Find(tokens, t => t.StartsWith('(') && t.EndsWith(')'));
        var rawIp = parenthesized?.Trim('(', ')') ?? (tokens.Length > 0 ? tokens[0] : null);
        if (rawIp is null || rawMac is null
            || NormalizeIp(rawIp) is not { } ip
            || NormalizeMac(rawMac) is not { } mac || mac == "00:00:00:00:00:00"
            || !IPAddress.TryParse(ip, out var address)
            || IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal
            || ip.StartsWith("169.254.", StringComparison.Ordinal) || IsNonUnicast(address))
        {
            return (null, null);
        }

        return (ip, mac);
    }

    private static bool IsNonUnicast(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetworkV6 ? address.IsIPv6Multicast : address.GetAddressBytes()[0] >= 224;

    /// <summary>The MAC address of the interface the SSH connection arrived on, or of the default route's.</summary>
    private static string? FindMac(Dictionary<string, List<string>> sections, string? serverIp, List<string> notes)
    {
        var macs = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in Lines(sections, "macs"))
        {
            var parts = line.Split(' ', 2, StringSplitOptions.TrimEntries);
            if (parts.Length == 2 && NormalizeMac(parts[1]) is { } mac && mac != "00:00:00:00:00:00")
            {
                macs[parts[0]] = mac;
            }
        }

        string? viaAddress = null;
        foreach (var line in Lines(sections, "addresses"))
        {
            var columns = line.Split(Whitespace, StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length >= 4 && serverIp is not null && NormalizeIp(columns[3].Split('/')[0]) == serverIp)
            {
                viaAddress = columns[1].TrimEnd(':').Split('@')[0];
                break;
            }
        }

        // "default via 10.0.0.1 dev eth0 proto dhcp ..."
        var route = First(sections, "route")?.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var devIndex = route is null ? -1 : Array.IndexOf(route, "dev");
        var viaRoute = devIndex >= 0 && devIndex + 1 < route!.Length ? route[devIndex + 1] : null;
        foreach (var candidate in new[] { viaAddress, viaRoute })
        {
            if (candidate is not null && macs.TryGetValue(candidate, out var mac))
            {
                return mac;
            }
        }

        var others = macs.Where(m => m.Key != "lo").ToList();
        if (others.Count == 1)
        {
            return others[0].Value;
        }

        notes.Add(others.Count == 0
            ? "No MAC address was found (the host doesn't expose /sys/class/net)."
            : "The host has several network interfaces and the one NKeeper reached couldn't be told apart, so no MAC address was picked.");
        return null;
    }

    private static Dictionary<string, List<string>> Sections(string output)
    {
        var sections = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        List<string>? current = null;
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.StartsWith("@@", StringComparison.Ordinal))
            {
                current = sections[line[2..].Trim()] = [];
            }
            else if (current is not null && line.Trim().Length > 0)
            {
                current.Add(line.Trim());
            }
        }

        return sections;
    }

    private static List<string> Lines(Dictionary<string, List<string>> sections, string name) =>
        sections.TryGetValue(name, out var lines) ? lines : [];

    private static string? First(Dictionary<string, List<string>> sections, string name) =>
        Lines(sections, name).FirstOrDefault() is { Length: > 0 } line ? line : null;

    /// <summary>"0.0.0.0:22", "[::]:22", "*:22", ":::22" → (address, port).</summary>
    private static (string Address, int Port)? SplitEndpoint(string endpoint)
    {
        var colon = endpoint.LastIndexOf(':');
        if (colon <= 0 || !int.TryParse(endpoint.AsSpan(colon + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
        {
            return null;
        }

        return (endpoint[..colon].Trim('[', ']'), port);
    }

    private static bool IsLoopback(string address)
    {
        var host = address.Split('%')[0];
        return host == "localhost" || (IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip));
    }

    /// <summary>Plain text form, without an IPv6 zone and with IPv4-mapped addresses as IPv4.</summary>
    private static string? NormalizeIp(string value) =>
        IPAddress.TryParse(value.Split('%')[0], out var ip) ? (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString() : null;

    /// <summary><c>AA:BB:CC:DD:EE:FF</c>, from six hex pairs with colons or dashes.</summary>
    internal static string? NormalizeMac(string value) =>
        MacPattern().IsMatch(value) ? value.Replace('-', ':').ToUpperInvariant() : null;

    [GeneratedRegex(@"^[0-9A-Fa-f]{2}(?:([:-])[0-9A-Fa-f]{2})(?:\1[0-9A-Fa-f]{2}){4}\z")]
    private static partial Regex MacPattern();

    private static IResult Problem(int status, string code, string detail, PresentedIdentity? presented = null)
    {
        var extensions = new Dictionary<string, object?> { ["code"] = code };
        if (presented is not null)
        {
            extensions["presented"] = presented;
        }

        return Results.Problem(statusCode: status, detail: detail, extensions: extensions);
    }

    private static string Code(ConnectFailure reason) => reason switch
    {
        ConnectFailure.HostKeyChanged => "host_key_changed",
        ConnectFailure.AuthenticationFailed => "authentication_failed",
        ConnectFailure.NoSecret => "no_secret",
        ConnectFailure.InvalidPrivateKey => "invalid_private_key",
        ConnectFailure.TimedOut => "timeout",
        ConnectFailure.JumpHostUnavailable => "jump_host_unavailable",
        _ => "unreachable",
    };
}

/// <summary>What the shell posts to a scan action (§7.26).</summary>
internal sealed record ScanRequest(Guid ServiceId, Guid? CredentialId, string? PromptReference);
