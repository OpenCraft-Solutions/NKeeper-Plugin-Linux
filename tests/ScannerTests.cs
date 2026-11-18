namespace NKeeper.Plugins.Linux.Tests;

/// <summary>docs/architecture.md §7.25: the internal scan's parsing, ported from 1.x's <c>InternalScanTests</c>.</summary>
public sealed class ScannerTests
{
    private const string Output = """

        @@hostname
        web01.example.com
        @@os
        Debian GNU/Linux 12 (bookworm)
        @@kernel
        Linux 6.1.0-18-amd64 x86_64
        @@connection
        192.0.2.1 50022 192.0.2.10 22
        @@addresses
        1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
        2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0\       valid_lft forever preferred_lft forever
        3: eth1    inet 10.0.0.10/24 brd 10.0.0.255 scope global eth1\       valid_lft forever preferred_lft forever
        @@macs
        eth0 52:54:00:12:34:56
        eth1 52:54:00:ab:cd:ef
        lo 00:00:00:00:00:00
        @@route
        default via 10.0.0.1 dev eth1 proto dhcp
        @@listening
        LISTEN 0      128          0.0.0.0:22        0.0.0.0:*
        LISTEN 0      128             [::]:22           [::]:*
        LISTEN 0      511          0.0.0.0:8080      0.0.0.0:*
        LISTEN 0      244        127.0.0.1:5432      0.0.0.0:*
        LISTEN 0      50                 *:3306            *:*
        @@uidmin
        1000
        @@users
        root:x:0:0:root:/root:/bin/bash
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        ops:x:1000:1000:Operations Team,,,:/home/ops:/bin/bash
        nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
        svc:x:1001:1001::/home/svc:/bin/false
        @@virt
        kvm
        @@cpus
        4
        @@memory
        online 8589934592
        memtotal 8000000
        @@serial
        VMware-56 4d
        @@neighbors
        192.0.2.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
        192.0.2.20 dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE
        192.0.2.20 dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE
        192.0.2.30 dev eth0 FAILED
        fe80::1 dev eth0 lladdr 00:11:22:33:44:66 router STALE
        @@end
        """;

    [Fact]
    public void A_linux_hosts_output_becomes_findings()
    {
        var findings = Scanner.Parse(Output)!;

        Assert.Equal("web01.example.com", findings.Hostname);
        Assert.Equal("192.0.2.10", findings.IpAddress);
        // The interface the connection arrived on, not the default route's.
        Assert.Equal("52:54:00:12:34:56", findings.MacAddress);
        Assert.Equal("Debian GNU/Linux 12 (bookworm)", findings.OperatingSystem);
        Assert.Equal((4, 8192), (findings.CpuCores, findings.MemoryMiB));
        Assert.Equal("kvm", findings.Virtualization);
        // A VM's serial number is its hypervisor's invention.
        Assert.Null(findings.SerialNumber);

        // Loopback-only listeners are left out; the rest are named, with the official plugins' types where they're theirs.
        Assert.Equal(
            [(22, "SSH", "ssh"), (3306, "MySQL / MariaDB", null), (8080, "HTTP (alternate)", "http")],
            findings.Ports.Select(p => (p.Port, p.Name, p.ServiceType)));
        Assert.Equal([("root", "root"), ("ops", "Operations Team")], findings.Users.Select(u => (u.Username, u.FullName)));

        // NKeeper's own address (the connection's other end) isn't a neighbour, and a failed lookup has no MAC.
        Assert.Equal([("192.0.2.20", "AA:BB:CC:DD:EE:02")], findings.Neighbors.Select(n => (n.IpAddress, n.MacAddress)));
    }

    [Fact]
    public void Output_that_didnt_reach_the_end_isnt_findings()
    {
        Assert.Null(Scanner.Parse("'sh' is not recognized as an internal or external command"));
        Assert.Null(Scanner.Parse(Output.Replace("@@end", string.Empty, StringComparison.Ordinal)));
    }

    [Fact]
    public void What_couldnt_be_read_becomes_notes()
    {
        var findings = Scanner.Parse("@@macs\neth0 52:54:00:00:00:01\neth1 52:54:00:00:00:02\n@@serial\n(unreadable)\n@@end\n")!;

        Assert.Null(findings.MacAddress);
        Assert.Null(findings.SerialNumber);
        Assert.Contains(findings.Notes, n => n.Contains("several network interfaces", StringComparison.Ordinal));
        Assert.Contains(findings.Notes, n => n.Contains("only be read as root", StringComparison.Ordinal));
        Assert.Contains(findings.Notes, n => n.Contains("listening ports couldn't be read", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("ABC1234", "ABC1234")]
    [InlineData("To Be Filled By O.E.M.", null)]
    [InlineData("0000000", null)]
    [InlineData("", null)]
    public void Firmware_placeholders_arent_serial_numbers(string value, string? expected) =>
        Assert.Equal(expected, Scanner.Serial(value));

    [Theory]
    [InlineData("? (192.0.2.5) at 00:11:22:33:44:55 [ether] on eth0", "192.0.2.5", "00:11:22:33:44:55")]
    [InlineData("192.0.2.6 dev eth0 lladdr 00:11:22:33:44:66 REACHABLE", "192.0.2.6", "00:11:22:33:44:66")]
    [InlineData("224.0.0.251 dev eth0 lladdr 01:00:5e:00:00:fb PERMANENT", null, null)]
    [InlineData("169.254.1.1 dev eth0 lladdr 00:11:22:33:44:77 STALE", null, null)]
    [InlineData("192.0.2.7 dev eth0 lladdr 00:00:00:00:00:00 STALE", null, null)]
    public void Neighbour_lines_from_ip_and_arp(string line, string? ip, string? mac) =>
        Assert.Equal((ip, mac), Scanner.ParseNeighborLine(line));
}
