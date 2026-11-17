namespace NKeeper.Plugins.Linux.Tests;

/// <summary>What the journal viewer and SELinux manager ask of a host, and what they make of the answers, in the real tools' formats.</summary>
public sealed class ParsingTests
{
    private const string Line = """{"__REALTIME_TIMESTAMP":"1793992564454931","PRIORITY":"4","_PID":"39","SYSLOG_IDENTIFIER":"nktest","_COMM":"logger","_HOSTNAME":"web1","MESSAGE":"event 5","__CURSOR":"s=de0;i=5df;b=52f;m=f8;t=65f;x=288","_SYSTEMD_UNIT":"nginx.service"}""";

    [Fact]
    public void JournalEntry_IsReadFromJson()
    {
        var entry = Journal.ParseEntry(Line)!;

        Assert.Equal("s=de0;i=5df;b=52f;m=f8;t=65f;x=288", entry.Cursor);
        Assert.Equal(new DateTimeOffset(2026, 11, 6, 19, 16, 4, TimeSpan.Zero).AddTicks(4549310), entry.Time);
        Assert.Equal((4, "nginx.service", "nktest", "39", "web1", "event 5"), (entry.Priority, entry.Unit, entry.Identifier, entry.Pid, entry.Hostname, entry.Message));
    }

    [Theory]
    [InlineData("""{"__CURSOR":"c","MESSAGE":[98,97,100,32,255,32,98]}""", "bad \uFFFD b")] // Not valid UTF-8.
    [InlineData("""{"__CURSOR":"c","MESSAGE":["one","two"]}""", "one")] // The field more than once.
    [InlineData("""{"__CURSOR":"c","MESSAGE":"\u001b[31mred\u001b[0m"}""", "red")] // Colours.
    [InlineData("""{"__CURSOR":"c"}""", "")]
    public void JournalMessages_OfOtherShapes_AreReadable(string line, string message) =>
        Assert.Equal(message, Journal.ParseEntry(line)!.Message);

    [Fact]
    public void AJournalMessageOver4KB_SaysSo() =>
        Assert.Contains("over 4 KB", Journal.ParseEntry("""{"__CURSOR":"c","MESSAGE":null}""")!.Message, StringComparison.Ordinal);

    [Theory]
    [InlineData("not json")]
    [InlineData("""{"MESSAGE":"no cursor"}""")]
    [InlineData("[1,2]")]
    public void WhatIsntAJournalEntry_IsSkipped(string line) => Assert.Null(Journal.ParseEntry(line));

    [Fact]
    public void JournalQuery_AsksForOnlyWhatsSet_NewestFirst()
    {
        var plain = Journal.ReadScript(new JournalQuery(null, null, null, null, null, null, null));
        Assert.EndsWith("$p journalctl --no-pager --output=json --reverse --lines=201", plain, StringComparison.Ordinal);

        var full = Journal.ReadScript(new JournalQuery(
            DateTimeOffset.FromUnixTimeSeconds(100), DateTimeOffset.FromUnixTimeSeconds(200), 3, "nginx.service", "sshd", "failed", "s=1;i=2"));
        Assert.EndsWith(
            "--lines=201 --since=@100 --until=@200 --priority=3 --unit='nginx.service' --identifier='sshd' --grep='failed' --after-cursor='s=1;i=2'",
            full,
            StringComparison.Ordinal);
    }

    [Fact]
    public void JournalValues_StayOneWord_AfterTheirOption()
    {
        var script = Journal.ReadScript(new JournalQuery(null, null, null, "x'; reboot; '", "-f", "$(reboot)", null));

        Assert.Contains(@"--unit='x'\''; reboot; '\'''", script, StringComparison.Ordinal);
        Assert.Contains("--identifier='-f'", script, StringComparison.Ordinal);
        Assert.Contains("--grep='$(reboot)'", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Following_HasNoTimeLimits_AndStartsNowOrFromTheCursor()
    {
        var times = DateTimeOffset.FromUnixTimeSeconds(100);

        var now = Journal.FollowScript(new JournalQuery(times, times, 3, null, null, null, null));
        Assert.EndsWith("exec $p journalctl --no-pager --output=json --follow --lines=0 --priority=3", now, StringComparison.Ordinal);

        var from = Journal.FollowScript(new JournalQuery(null, null, null, null, null, null, "s=1"));
        Assert.EndsWith("--follow --after-cursor='s=1'", from, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("s=de0;i=5df;b=52f;m=f8;t=65f;x=288", true)]
    [InlineData(null, true)]
    [InlineData("s=1'; reboot", false)]
    [InlineData("", false)]
    public void JournalCursors_AreChecked(string? cursor, bool valid) => Assert.Equal(valid, Journal.IsCursor(cursor));

    [Theory]
    [InlineData("journalctl: unrecognized option '--grep=x'", "needs systemd 237")]
    [InlineData("No journal files were opened due to insufficient permissions.", "systemd-journal group")]
    [InlineData("Bad pattern \"(\": missing closing parenthesis", "isn't a valid regular expression")]
    [InlineData("Something else", "Something else")]
    public void JournalErrors_SayWhatToDo(string message, string expected) =>
        Assert.Contains(expected, Journal.Explain(message), StringComparison.Ordinal);

    [Fact]
    public void Denial_IsReadFromAnAvcRecord()
    {
        var denial = Selinux.ParseDenial(
            """type=AVC msg=audit(1730000000.123:456): avc:  denied  { read write } for  pid=123 comm="nginx" name="index.html" dev="dm-0" ino=99 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0""")!;

        Assert.Equal((456, "AVC", true), (denial.EventId, denial.Type, denial.Blocked));
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1730000000123), denial.Time);
        Assert.Equal(["read", "write"], denial.Permissions);
        Assert.Equal(("nginx", "123", "index.html", "file"), (denial.Process, denial.Pid, denial.Target, denial.TargetClass));
        Assert.Equal(("system_u:system_r:httpd_t:s0", "unconfined_u:object_r:user_home_t:s0"), (denial.SourceContext, denial.TargetContext));
    }

    [Fact]
    public void Denial_WithoutQuotes_AsAusearchMayPrint_IsReadTheSame()
    {
        var denial = Selinux.ParseDenial(
            "type=AVC msg=audit(1730000000.123:456): avc:  denied  { read } for  pid=123 comm=nginx name=index.html dev=dm-0 ino=99 scontext=a:b:c:s0 tcontext=d:e:f:s0 tclass=file permissive=0")!;

        Assert.Equal(("nginx", "index.html"), (denial.Process, denial.Target));
    }

    [Fact]
    public void Denial_FromSystemd_IsReadFromAUserAvcRecord()
    {
        var denial = Selinux.ParseDenial(
            """type=USER_AVC msg=audit(1730000100.500:457): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:init_t:s0 msg='avc:  denied  { start } for auid=n/a uid=0 gid=0 path="/usr/lib/systemd/system/x.service" cmdline="" function="mac_selinux_filter" scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:etc_t:s0 tclass=service permissive=1 exe="/usr/lib/systemd/systemd" sauid=0 hostname=? addr=? terminal=?'""")!;

        Assert.Equal(("USER_AVC", false, "/usr/lib/systemd/systemd", "/usr/lib/systemd/system/x.service", "service"), (denial.Type, denial.Blocked, denial.Process, denial.Target, denial.TargetClass));
        Assert.Equal(["start"], denial.Permissions);
    }

    [Fact]
    public void WhatIsGranted_IsntADenial_ButAnSelinuxErrorIs()
    {
        Assert.Null(Selinux.ParseDenial("type=AVC msg=audit(1730000200.100:458): avc:  granted  { setenforce } for  pid=9 comm=\"setenforce\" scontext=x:y:z:s0 tcontext=x:y:z:s0 tclass=security"));

        var error = Selinux.ParseDenial("type=SELINUX_ERR msg=audit(1730000300.000:459): op=security_compute_sid invalid_context=x:y:z:s0")!;
        Assert.Equal(("SELINUX_ERR", 459), (error.Type, error.EventId));
        Assert.Empty(error.Permissions);
    }

    [Theory]
    [InlineData("module nkfix 1.0;\n\nrequire {\n}\n", "nkfix")]
    [InlineData("\n# A comment first\n\nmodule my_fix 1.2.3 ;\n", "my_fix")]
    [InlineData("policy_module(foo, 1.0)\n", null)] // Needs the policy's development Makefile.
    [InlineData("allow a b:c d;\n", null)]
    [InlineData("# only comments\n", null)]
    public void APolicysName_ComesFromItsSource(string source, string? name) => Assert.Equal(name, Selinux.DeclaredModule(source));

    [Theory]
    [InlineData("nginx_fix", true)]
    [InlineData("A1", true)]
    [InlineData("1abc", false)]
    [InlineData("bad name", false)]
    [InlineData("x;reboot", false)]
    [InlineData("-f", false)]
    [InlineData("../x", false)]
    [InlineData("", false)]
    public void PolicyNames_AreChecked(string name, bool valid) => Assert.Equal(valid, Selinux.IsModuleName(name));

    [Fact]
    public void Status_TurnsItsTimes_IntoTheHostsOwnFormat()
    {
        var script = Selinux.StatusScript(DateTimeOffset.FromUnixTimeSeconds(100), DateTimeOffset.FromUnixTimeSeconds(200));

        Assert.Contains("--raw -ts $(LC_ALL=C date -d @100 '+%x %H:%M:%S') -te $(LC_ALL=C date -d @200 '+%x %H:%M:%S')", script, StringComparison.Ordinal);
    }

    [Fact]
    public void InstallingAPolicy_CarriesItsSourceSafely()
    {
        const string source = "module x 1.0;\n# '; reboot; '\n";

        var script = Selinux.InstallScript("x", source);

        Assert.DoesNotContain("reboot", script, StringComparison.Ordinal);
        Assert.Contains(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(source)), script, StringComparison.Ordinal);
    }
}

/// <summary>Paths on the host, as the Files tool resolves them (ported from 1.x's SftpController).</summary>
public sealed class RemotePathTests
{
    [Theory]
    [InlineData("/home/me", null, "/home/me")]
    [InlineData("/home/me", "", "/home/me")]
    [InlineData("/home/me", "docs", "/home/me/docs")]
    [InlineData("/home/me", "../../etc//./passwd", "/etc/passwd")]
    [InlineData("/home/me", "/../..", "/")]
    [InlineData("/C:/Users/me", "..", "/C:/Users")]
    public void Paths_resolve_from_the_home_folder(string home, string? path, string expected) =>
        Assert.Equal(expected, RemotePath.Resolve(home, path));

    [Theory]
    [InlineData("/", null)]
    [InlineData("/etc", "/")]
    [InlineData("/C:/Users", "/C:")]
    public void A_folder_has_a_parent_except_the_root(string path, string? parent) => Assert.Equal(parent, RemotePath.ParentOf(path));

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("a/b")]
    public void Names_are_one_segment(string name) => Assert.Throws<ToolException>(() => RemotePath.CheckName(name));
}
