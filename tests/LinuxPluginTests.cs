using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using NKeeper.Testing;
using Npgsql;

namespace NKeeper.Plugins.Linux.Tests;

/// <summary>
/// docs/architecture.md §7.25: the real <c>linux</c> plugin, packaged by its build and loaded with the released ssh
/// plugin into NKeeper's test server, running its tools over core's stream sessions on a (fake) Linux host. Ported
/// from 1.x's SftpTests and LinuxToolsTests.
/// </summary>
public sealed class LinuxPluginTests(PostgresFixture postgres, LinuxHostFixture linux) : IClassFixture<PostgresFixture>, IClassFixture<LinuxHostFixture>, IAsyncLifetime
{
    private const string Avc = """type=AVC msg=audit(1730000000.123:456): avc:  denied  { read } for  pid=123 comm="nginx" name="index.html" dev="dm-0" ino=99 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0""";

    private const string Policy = "module nginx_fix 1.0;\n\nrequire {\n\ttype httpd_t;\n}\n";

    private TestServer _server = null!;
    private string _cookie = string.Empty;
    private string _connectionString = string.Empty;

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    private static string Entry(string cursor, string message, int priority = 6, long micros = 1793992564454931) =>
        $$"""{"__CURSOR":"{{cursor}}","__REALTIME_TIMESTAMP":"{{micros}}","PRIORITY":"{{priority}}","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"{{message}}"}""" + "\n";

    public async ValueTask InitializeAsync()
    {
        await linux.ResetAsync();
        _connectionString = await postgres.CreateDatabaseAsync();
        var options = new TestServerOptions { ConnectionString = _connectionString };
        foreach (var package in DevelopmentKeys.BuiltPackages())
        {
            options.PluginPackages.Add(package);
        }

        options.PluginPackages.Add(await SshPluginRelease.PathAsync(Token));
        _server = await TestServer.StartAsync(options, Token);
        _cookie = await SignInAsync(TestServer.AdminUserName, TestServer.AdminPassword);
    }

    public async ValueTask DisposeAsync() => await _server.DisposeAsync();

    // ---- The plugin ----

    [Fact]
    public async Task The_plugin_contributes_its_tools_on_ssh_services()
    {
        using var admin = await _server.SignedInClientAsync(Token);
        var plugins = await admin.Http.GetFromJsonAsync<JsonElement>(new Uri("/api/plugins", UriKind.Relative), Token);
        var plugin = plugins.EnumerateArray().Single(p => p.GetProperty("id").GetString() == "linux");
        Assert.Equal("loaded", plugin.GetProperty("state").GetString());
        Assert.Equal("loaded", plugins.EnumerateArray().Single(p => p.GetProperty("id").GetString() == "ssh").GetProperty("state").GetString());

        Assert.Equal(
            [("linux-files", "Files"), ("linux-journal", "Journal"), ("linux-selinux", "SELinux")],
            plugin.GetProperty("sessionTypes").EnumerateArray().Select(t => (t.GetProperty("id").GetString(), t.GetProperty("label").GetString())));
        Assert.All(plugin.GetProperty("sessionTypes").EnumerateArray(), t => Assert.Equal("ssh", Assert.Single(t.GetProperty("serviceTypes").EnumerateArray()).GetString()));
        Assert.Equal(
            [("linux.files", false), ("linux.journal", false), ("linux.selinux", false), ("linux.scan", true)],
            plugin.GetProperty("hostActions").EnumerateArray().Select(a => (a.GetProperty("id").GetString(), a.GetProperty("scan").GetBoolean())));

        // Its frontend is served from the verified package.
        using var module = await admin.Http.GetAsync(new Uri(plugin.GetProperty("frontendEntry").GetString()!, UriKind.Relative), Token);
        Assert.Equal(HttpStatusCode.OK, module.StatusCode);
        Assert.Contains("@nkeeper/sdk", await module.Content.ReadAsStringAsync(Token), StringComparison.Ordinal);
    }

    // ---- Files ----

    [Fact]
    public async Task Files_lists_creates_uploads_renames_and_deletes()
    {
        var host = await CreateHostAsync();
        await using var files = await OpenAsync("linux-files", host);

        var home = Data(await files.RequestAsync("list"));
        Assert.Equal("/config", home.GetProperty("path").GetString());
        Assert.Equal("/", home.GetProperty("parent").GetString());
        Assert.Contains(home.GetProperty("entries").EnumerateArray(), e => e.GetProperty("name").GetString() == "files" && e.GetProperty("kind").GetString() == "directory");

        Data(await files.RequestAsync("mkdir", new { path = "files/new" }));
        Assert.Equal("The account isn't allowed to do that with /etc/x.", Error(await files.RequestAsync("mkdir", new { path = "/etc/x" })));
        Assert.Contains("already exists", Error(await files.RequestAsync("mkdir", new { path = "files/new" })), StringComparison.Ordinal);

        // An upload in chunks, each acknowledged; the last answers the request.
        var content = Encoding.UTF8.GetBytes(new string('x', 1500) + "end");
        var upload = await UploadAsync(files, "/config/files/new", "a.txt", content);
        Assert.Equal("/config/files/new/a.txt", Data(upload).GetProperty("path").GetString());
        Assert.Equal("x", (await linux.ExecAsync("head -c 1 /config/files/new/a.txt")).Trim());
        Assert.Equal(content.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), (await linux.ExecAsync("wc -c < /config/files/new/a.txt")).Trim());

        // A file that exists isn't replaced unless asked.
        Assert.Contains("already exists", Error(await files.RequestAsync("upload", new { path = "/config/files/new", name = "a.txt", size = 3 })), StringComparison.Ordinal);
        Data(await UploadAsync(files, "/config/files/new", "a.txt", "new"u8.ToArray(), overwrite: true));
        Assert.Equal("new", await linux.ExecAsync("cat /config/files/new/a.txt"));

        var listed = Data(await files.RequestAsync("list", new { path = "/config/files/new" })).GetProperty("entries");
        var file = Assert.Single(listed.EnumerateArray());
        Assert.Equal(("a.txt", "file", 3, 9), (file.GetProperty("name").GetString(), file.GetProperty("kind").GetString(), file.GetProperty("size").GetInt32(), file.GetProperty("permissions").GetString()!.Length));

        Assert.Contains("isn't empty", Error(await files.RequestAsync("delete", new { path = "/config/files/new" })), StringComparison.Ordinal);
        Assert.Equal("/config/files/new/b.txt", Data(await files.RequestAsync("rename", new { path = "/config/files/new/a.txt", newPath = "b.txt" })).GetProperty("path").GetString());
        Data(await files.RequestAsync("delete", new { path = "/config/files/new/b.txt" }));
        Data(await files.RequestAsync("delete", new { path = "/config/files/new" }));
        Assert.Contains("doesn't exist", Error(await files.RequestAsync("list", new { path = "/config/files/new" })), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Files_reports_folder_sizes_as_each_is_known()
    {
        await linux.ExecAsync("mkdir -p /config/files/a/deep /config/files/b && head -c 1000 /dev/zero > /config/files/a/one && head -c 500 /dev/zero > /config/files/a/deep/two && chown -R tester /config/files");
        var host = await CreateHostAsync();
        await using var files = await OpenAsync("linux-files", host);

        Data(await files.RequestAsync("sizes", new { paths = new[] { "/config/files/a", "/config/files/b", "/proc" } }));

        var sizes = files.Received.Where(m => m.GetProperty("type").GetString() == "size")
            .ToDictionary(m => m.GetProperty("path").GetString()!, m => (m.GetProperty("size").GetInt64(), m.GetProperty("complete").GetBoolean()));
        Assert.Equal((1500L, true), sizes["/config/files/a"]);
        Assert.Equal((0L, true), sizes["/config/files/b"]);
        Assert.Equal((0L, false), sizes["/proc"]);
    }

    [Fact]
    public async Task A_download_link_streams_the_file_once_for_the_same_user_while_the_session_is_open()
    {
        await linux.ExecAsync("printf 'hello download' > /config/files/d.txt && mkdir -p /config/files/z/sub && printf one > /config/files/z/1.txt && printf two > /config/files/z/sub/2.txt && chown -R tester /config/files");
        var host = await CreateHostAsync();
        await using var files = await OpenAsync("linux-files", host);
        using var http = new HttpClient { BaseAddress = _server.BaseAddress };

        var url = Data(await files.RequestAsync("download", new { path = "/config/files/d.txt" })).GetProperty("url").GetString()!;
        using (var response = await GetAsync(http, url, _cookie))
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("hello download", await response.Content.ReadAsStringAsync(Token));
            Assert.Equal("d.txt", response.Content.Headers.ContentDisposition?.FileNameStar ?? response.Content.Headers.ContentDisposition?.FileName);
        }

        // Once only.
        using (var again = await GetAsync(http, url, _cookie))
        {
            Assert.Equal(HttpStatusCode.NotFound, again.StatusCode);
        }

        // A folder comes as a zip.
        var zipUrl = Data(await files.RequestAsync("download", new { path = "/config/files/z" })).GetProperty("url").GetString()!;
        using (var zipped = await GetAsync(http, zipUrl, _cookie))
        {
            Assert.Equal(HttpStatusCode.OK, zipped.StatusCode);
            using var zip = new System.IO.Compression.ZipArchive(await zipped.Content.ReadAsStreamAsync(Token));
            Assert.Equal(["1.txt", "sub/2.txt"], zip.Entries.Select(e => e.FullName).Order());
        }

        // Another user, even one who can use the host, can't use it.
        var bobId = await CreateUserAsync("bob");
        using (var admin = await _server.SignedInClientAsync(Token))
        {
            (await admin.SendAsync(HttpMethod.Put, $"/api/users/{bobId}/grants", new[] { new { hostId = Id(host), level = "use" } }, Token)).EnsureSuccessStatusCode();
        }

        var bobCookie = await SignInAsync("bob", BobPassword);
        var forBob = Data(await files.RequestAsync("download", new { path = "/config/files/d.txt" })).GetProperty("url").GetString()!;
        using (var bob = await GetAsync(http, forBob, bobCookie))
        {
            Assert.Equal(HttpStatusCode.NotFound, bob.StatusCode);
        }

        // Closing the session ends its links.
        var late = Data(await files.RequestAsync("download", new { path = "/config/files/d.txt" })).GetProperty("url").GetString()!;
        await files.DisposeAsync();
        await Task.Delay(3000, Token); // The server notices the closed socket and ends the session.
        using (var closed = await GetAsync(http, late, _cookie))
        {
            Assert.Equal(HttpStatusCode.NotFound, closed.StatusCode);
        }
    }

    // ---- Journal ----

    [Fact]
    public async Task Journal_reads_entries_with_sudo_and_passes_its_filters()
    {
        await linux.WriteAsync("journal", Entry("s=2", "newest", 3) + Entry("s=1", "older"));
        var host = await CreateHostAsync();
        await using var journal = await OpenAsync("linux-journal", host);

        var page = Data(await journal.RequestAsync("read"));
        Assert.Equal(["newest", "older"], page.GetProperty("entries").EnumerateArray().Select(e => e.GetProperty("message").GetString()));
        Assert.Equal(3, page.GetProperty("entries")[0].GetProperty("priority").GetInt32());
        Assert.False(page.GetProperty("hasMore").GetBoolean());
        Assert.False(page.GetProperty("limited").GetBoolean());

        Data(await journal.RequestAsync("read", new
        {
            since = "2026-11-06T18:00:00Z",
            until = "2026-11-06T19:00:00Z",
            maxPriority = 3,
            unit = "ssh.service",
            identifier = "sshd",
            search = "newest",
            after = "s=9;i=1",
        }));
        var args = (await linux.ReadAsync("journalctl-args")).Trim().Split('\n')[^1];
        Assert.Contains($"--since=@{new DateTimeOffset(2026, 11, 6, 18, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds()}", args, StringComparison.Ordinal);
        Assert.Contains("--priority=3 --unit=ssh.service --identifier=sshd --grep=newest --after-cursor=s=9;i=1", args, StringComparison.Ordinal);

        // A search matching nothing is no entries, not an error; a bad one says so.
        Assert.Equal(0, Data(await journal.RequestAsync("read", new { search = "nothing" })).GetProperty("entries").GetArrayLength());
        Assert.Contains("valid regular expression", Error(await journal.RequestAsync("read", new { search = "(" })), StringComparison.Ordinal);

        // Refused before they reach the host.
        var before = await linux.ReadAsync("journalctl-args");
        Assert.Contains("start is after the stop", Error(await journal.RequestAsync("read", new { since = "2026-11-06T19:00:00Z", until = "2026-11-06T18:00:00Z" })), StringComparison.Ordinal);
        Assert.Contains("cursor", Error(await journal.RequestAsync("read", new { after = "x'; reboot" })), StringComparison.Ordinal);
        Assert.Contains("0 (emergency) to 7", Error(await journal.RequestAsync("read", new { maxPriority = 9 })), StringComparison.Ordinal);
        Assert.Equal(before, await linux.ReadAsync("journalctl-args"));
    }

    [Fact]
    public async Task Journal_over_a_page_says_more_remain()
    {
        await linux.WriteAsync("journal", string.Concat(Enumerable.Range(0, Journal.PageSize + 1).Select(i => Entry($"s={i}", $"entry {i}"))));
        var host = await CreateHostAsync();
        await using var journal = await OpenAsync("linux-journal", host);

        var page = Data(await journal.RequestAsync("read"));

        Assert.Equal(Journal.PageSize, page.GetProperty("entries").GetArrayLength());
        Assert.True(page.GetProperty("hasMore").GetBoolean());
    }

    [Fact]
    public async Task Journal_without_sudo_says_when_it_cant_read_it_or_reads_part_of_it()
    {
        await linux.WriteAsync("journal", Entry("s=1", "mine"));
        await linux.RemoveSudoAsync();
        var host = await CreateHostAsync();
        await using var journal = await OpenAsync("linux-journal", host);

        Assert.Contains("systemd-journal group", Error(await journal.RequestAsync("read")), StringComparison.Ordinal);

        await linux.ExecAsync("touch /var/lib/fake-linux/journal-open");
        var page = Data(await journal.RequestAsync("read"));
        Assert.True(page.GetProperty("limited").GetBoolean());
        Assert.Equal("mine", page.GetProperty("entries")[0].GetProperty("message").GetString());
    }

    [Fact]
    public async Task Following_streams_new_entries_from_the_cursor_and_stop_ends_journalctl()
    {
        await linux.WriteAsync("journal-new", Entry("s=5", "just happened"));
        var host = await CreateHostAsync();
        await using var journal = await OpenAsync("linux-journal", host);

        Data(await journal.RequestAsync("follow", new { after = "s=4", maxPriority = 3 }, id: "f1"));
        var entry = await NextOfAsync(journal, "entry");
        Assert.Equal(("f1", "just happened"), (entry.GetProperty("id").GetString(), entry.GetProperty("entry").GetProperty("message").GetString()));
        var args = (await linux.ReadAsync("journalctl-args")).Trim().Split('\n')[^1];
        Assert.Contains("--follow --priority=3 --after-cursor=s=4", args, StringComparison.Ordinal);

        Data(await journal.RequestAsync("stop"));
        await GoneAsync("sleep 300");
    }

    [Fact]
    public async Task Closing_the_tab_ends_journalctl()
    {
        var host = await CreateHostAsync();
        var journal = await OpenAsync("linux-journal", host);
        Data(await journal.RequestAsync("follow"));
        await WaitForAsync("sleep 300");

        await journal.DisposeAsync();

        await GoneAsync("sleep 300");
    }

    // ---- SELinux ----

    [Fact]
    public async Task Selinux_shows_its_mode_modules_and_denials()
    {
        await linux.WriteAsync("audit.log", Avc + "\ntype=AVC msg=audit(1730000900.000:460): avc:  denied  { write } for  pid=9 comm=\"cat\" name=\"x\" scontext=a:b:c:s0 tcontext=d:e:f:s0 tclass=file permissive=1\n");
        var host = await CreateHostAsync();
        await using var selinux = await OpenAsync("linux-selinux", host);

        var status = Data(await selinux.RequestAsync("status", new { since = "2024-01-01T00:00:00Z", until = "2030-01-01T00:00:00Z" }));

        Assert.Equal("Enforcing", status.GetProperty("mode").GetString());
        Assert.Equal(["base", "httpd", "my_old_fix"], status.GetProperty("modules").EnumerateArray().Select(m => m.GetProperty("name").GetString()));
        var denials = status.GetProperty("denials");
        Assert.Equal([460L, 456L], denials.EnumerateArray().Select(d => d.GetProperty("eventId").GetInt64()));
        Assert.False(denials[0].GetProperty("blocked").GetBoolean());
        var args = (await linux.ReadAsync("ausearch-args")).Trim().Split('\n')[^1];
        Assert.Matches(@"-ts \d\d/\d\d/\d\d \d\d:\d\d:\d\d -te \d\d/\d\d/\d\d \d\d:\d\d:\d\d", args);

        // No audit log is a problem worth saying; no denials isn't.
        await linux.WriteAsync("audit.log", string.Empty);
        Assert.Equal(JsonValueKind.Null, Data(await selinux.RequestAsync("status")).GetProperty("auditProblem").ValueKind);
        await linux.ExecAsync("touch /var/lib/fake-linux/no-audit-log");
        Assert.Contains("auditd", Data(await selinux.RequestAsync("status")).GetProperty("auditProblem").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Selinux_generates_a_policy_then_installs_and_removes_it()
    {
        await linux.WriteAsync("audit.log", Avc + "\n");
        var host = await CreateHostAsync();
        await using var selinux = await OpenAsync("linux-selinux", host);

        var source = Data(await selinux.RequestAsync("generate", new { name = "nginx_fix", eventIds = new[] { 456 } })).GetProperty("source").GetString()!;
        Assert.Contains("module nginx_fix 1.0;", source, StringComparison.Ordinal);
        Assert.Contains("allow httpd_t user_home_t:file read;", source, StringComparison.Ordinal);
        Assert.DoesNotContain("nginx_fix", await linux.ReadAsync("modules"), StringComparison.Ordinal);

        Data(await selinux.RequestAsync("install", new { name = "nginx_fix", source }));
        Assert.Contains("400 nginx_fix", await linux.ReadAsync("modules"), StringComparison.Ordinal);

        Data(await selinux.RequestAsync("remove", new { name = "nginx_fix", priority = 400 }));
        Assert.DoesNotContain("nginx_fix", await linux.ReadAsync("modules"), StringComparison.Ordinal);

        Assert.Contains("found nothing to allow", Error(await selinux.RequestAsync("generate", new { name = "nginx_fix", eventIds = new[] { 999 } })), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Selinux_refuses_what_it_shouldnt_do()
    {
        var host = await CreateHostAsync();
        await using var selinux = await OpenAsync("linux-selinux", host);
        var before = await linux.ReadAsync("modules");

        Assert.Contains("letters, digits", Error(await selinux.RequestAsync("generate", new { name = "nginx;reboot", eventIds = new[] { 456 } })), StringComparison.Ordinal);
        Assert.Contains("declaring the module", Error(await selinux.RequestAsync("install", new { name = "nginx_fix", source = "allow a b:c d;" })), StringComparison.Ordinal);
        Assert.Contains("syntax error", Error(await selinux.RequestAsync("install", new { name = "broken", source = "module broken 1.0;\nrequire { type x_t" })), StringComparison.Ordinal);
        Assert.Contains("distribution", Error(await selinux.RequestAsync("install", new { name = "httpd", source = "module httpd 1.0;\n" })), StringComparison.Ordinal);
        Assert.Contains("distribution", Error(await selinux.RequestAsync("remove", new { name = "base", priority = 100 })), StringComparison.Ordinal);
        Assert.Contains("no module", Error(await selinux.RequestAsync("remove", new { name = "nothing_here", priority = 400 })), StringComparison.Ordinal);

        // Judged by the host's list, not semodule's exit status.
        await linux.ExecAsync("touch /var/lib/fake-linux/silent-install");
        Assert.Contains("doesn't list nginx_fix", Error(await selinux.RequestAsync("install", new { name = "nginx_fix", source = Policy })), StringComparison.Ordinal);
        Assert.Equal(before, await linux.ReadAsync("modules"));
    }

    [Fact]
    public async Task Selinux_on_a_host_without_it_or_without_root_says_so()
    {
        var host = await CreateHostAsync();
        await using var selinux = await OpenAsync("linux-selinux", host);

        await linux.ExecAsync("mv /usr/local/bin/getenforce /usr/local/bin/getenforce.off");
        try
        {
            Assert.Equal(JsonValueKind.Null, Data(await selinux.RequestAsync("status")).GetProperty("mode").ValueKind);
        }
        finally
        {
            await linux.ExecAsync("mv /usr/local/bin/getenforce.off /usr/local/bin/getenforce");
        }

        await linux.RemoveSudoAsync();
        Assert.Contains("needs root", Error(await selinux.RequestAsync("status")), StringComparison.Ordinal);
    }

    // ---- Scan ----

    [Fact]
    public async Task A_scan_asks_to_trust_the_key_then_reads_the_host_and_is_audited()
    {
        // The image's own login is in the system range (911, below UID_MIN), which a scan leaves out, as 1.x did.
        await linux.ExecAsync("id ops >/dev/null 2>&1 || adduser -D -u 1500 -g 'Operations Team' -s /bin/bash ops");
        var host = await CreateHostAsync();
        using var admin = await _server.SignedInClientAsync(Token);
        var body = new { serviceId = ServiceId(host), credentialId = CredentialId(host) };

        using (var unknown = await admin.SendAsync(HttpMethod.Post, $"/api/p/linux/hosts/{Id(host)}/scan", body, Token))
        {
            Assert.Equal(HttpStatusCode.Conflict, unknown.StatusCode);
            var problem = await unknown.Content.ReadFromJsonAsync<JsonElement>(Token);
            Assert.Equal("host_key_unknown", problem.GetProperty("code").GetString());
            var presented = problem.GetProperty("presented");
            using var trusted = await admin.SendAsync(
                HttpMethod.Post,
                $"/api/hosts/{Id(host)}/services/{ServiceId(host)}/trusted-keys",
                new { algorithm = presented.GetProperty("algorithm").GetString(), fingerprint = presented.GetProperty("fingerprint").GetString() },
                Token);
            Assert.True(trusted.IsSuccessStatusCode, await trusted.Content.ReadAsStringAsync(Token));
        }

        using var scanned = await admin.SendAsync(HttpMethod.Post, $"/api/p/linux/hosts/{Id(host)}/scan", body, Token);
        Assert.True(scanned.IsSuccessStatusCode, await scanned.Content.ReadAsStringAsync(Token));
        var findings = await scanned.Content.ReadFromJsonAsync<JsonElement>(Token);

        Assert.False(string.IsNullOrEmpty(findings.GetProperty("hostname").GetString()));
        Assert.True(findings.GetProperty("cpuCores").GetInt32() > 0);
        Assert.Equal(
            [("root", "root"), ("ops", "Operations Team")],
            findings.GetProperty("users").EnumerateArray().Select(u => (u.GetProperty("username").GetString(), u.GetProperty("fullName").GetString())));
        Assert.Contains(findings.GetProperty("ports").EnumerateArray(), p => p.GetProperty("port").GetInt32() == LinuxHostFixture.ContainerSshPort);

        await using var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(Token);
        await using var command = new NpgsqlCommand("SELECT detail FROM core.audit_events WHERE action = 'linux.scan'", connection);
        Assert.Contains("ports", (string?)await command.ExecuteScalarAsync(Token), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_scan_of_a_host_that_isnt_linux_says_so()
    {
        await linux.ExecAsync("touch /var/lib/fake-linux/not-linux");
        var host = await CreateHostAsync();
        await using (await OpenAsync("linux-files", host))
        {
            // Opening a tool trusts the host's key.
        }

        using var admin = await _server.SignedInClientAsync(Token);
        using var refused = await admin.SendAsync(HttpMethod.Post, $"/api/p/linux/hosts/{Id(host)}/scan", new { serviceId = ServiceId(host), credentialId = CredentialId(host) }, Token);

        Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
        var problem = await refused.Content.ReadFromJsonAsync<JsonElement>(Token);
        Assert.Equal("not_linux", problem.GetProperty("code").GetString());
        Assert.Contains("isn't Linux", problem.GetProperty("detail").GetString(), StringComparison.Ordinal);
    }

    // ---- Hosts that aren't Linux ----

    [Theory]
    [InlineData("linux-journal")]
    [InlineData("linux-selinux")]
    public async Task A_script_tool_on_a_host_that_isnt_linux_says_so_and_ends(string sessionType)
    {
        await linux.ExecAsync("touch /var/lib/fake-linux/not-linux");
        var host = await CreateHostAsync();
        await using var tool = await OpenAsync(sessionType, host);

        var fatal = await tool.NextAsync();

        Assert.Equal("fatal", fatal.GetProperty("type").GetString());
        Assert.Contains("isn't Linux (it says it's MINGW64_NT-10.0-26100)", fatal.GetProperty("message").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Files_works_on_a_host_that_isnt_linux()
    {
        await linux.ExecAsync("touch /var/lib/fake-linux/not-linux");
        var host = await CreateHostAsync();
        await using var files = await OpenAsync("linux-files", host);

        Assert.Equal("/config", Data(await files.RequestAsync("list")).GetProperty("path").GetString());
    }

    // ---- Access ----

    [Fact]
    public async Task A_user_without_access_to_the_host_cant_open_the_tools()
    {
        var host = await CreateHostAsync();
        await CreateUserAsync("bob");
        var bob = await SignInAsync("bob", BobPassword);

        await using var tool = await SessionClient.ConnectAsync(_server, bob, "linux-selinux");
        await tool.SendAsync(new { type = "start", hostId = Id(host), serviceId = ServiceId(host), credentialId = CredentialId(host) });

        var error = await tool.NextAsync();
        Assert.Equal(("error", "host_not_found"), (error.GetProperty("type").GetString(), error.GetProperty("code").GetString()));
        Assert.Contains("my_old_fix", await linux.ReadAsync("modules"), StringComparison.Ordinal);
    }

    // ---- Helpers ----

    private const string BobPassword = "Bob-Passw0rd-123";

    private static JsonElement Data(JsonElement reply)
    {
        Assert.True(reply.GetProperty("type").GetString() == "reply", reply.GetRawText());
        return reply.TryGetProperty("data", out var data) ? data : default;
    }

    private static string Error(JsonElement reply)
    {
        Assert.True(reply.GetProperty("type").GetString() == "error", reply.GetRawText());
        return reply.GetProperty("message").GetString()!;
    }

    private static Guid Id(JsonElement host) => host.GetProperty("id").GetGuid();

    private static Guid ServiceId(JsonElement host) => host.GetProperty("services")[0].GetProperty("id").GetGuid();

    private static Guid CredentialId(JsonElement host) => host.GetProperty("credentials")[0].GetProperty("id").GetGuid();

    private static async Task<JsonElement> UploadAsync(SessionClient files, string folder, string name, byte[] content, bool overwrite = false)
    {
        // Small chunks, so a file of a few KB takes several, each acknowledged before the next.
        const int Chunk = 1024;
        var id = $"u{Guid.NewGuid():N}";
        await files.SendRequestAsync("upload", new { path = folder, name, size = content.Length, overwrite }, id);
        var sent = 0;
        var acks = 0;
        while (true)
        {
            var message = await files.NextAsync();
            if (message.GetProperty("id").GetString() != id)
            {
                files.Received.Add(message);
                continue;
            }

            switch (message.GetProperty("type").GetString())
            {
                case "ack":
                    acks++;
                    Assert.Equal(sent, message.GetProperty("received").GetInt32());
                    goto case "ready";
                case "ready":
                    var next = content.AsMemory(sent, Math.Min(Chunk, content.Length - sent)).ToArray();
                    sent += next.Length;
                    await files.SendBinaryAsync(next);
                    break;
                default:
                    Assert.Equal(Math.Max(0, ((content.Length + Chunk - 1) / Chunk) - 1), acks);
                    return message;
            }
        }
    }

    private async Task<JsonElement> CreateHostAsync()
    {
        using var admin = await _server.SignedInClientAsync(Token);
        using var created = await admin.SendAsync(HttpMethod.Post, "/api/hosts", new
        {
            name = $"linux-{Guid.NewGuid():N}"[..20],
            ipAddress = LinuxHostFixture.Address,
            services = new[] { new { type = "ssh", port = linux.Port, settings = new { } } },
            credentials = new[] { new { username = LinuxHostFixture.UserName, password = LinuxHostFixture.Password } },
        }, Token);
        Assert.True(created.StatusCode == HttpStatusCode.Created, await created.Content.ReadAsStringAsync(Token));
        return await created.Content.ReadFromJsonAsync<JsonElement>(Token);
    }

    /// <summary>Opens a tool on the host's SSH service with its credential, trusting the host key when asked.</summary>
    private async Task<SessionClient> OpenAsync(string sessionType, JsonElement host)
    {
        var tool = await SessionClient.ConnectAsync(_server, _cookie, sessionType);
        await tool.SendAsync(new { type = "start", hostId = Id(host), serviceId = ServiceId(host), credentialId = CredentialId(host) });
        while (true)
        {
            var message = await tool.NextAsync();
            switch (message.GetProperty("type").GetString())
            {
                case "hostKey":
                    await tool.SendAsync(new { type = "hostKeyDecision", trust = true });
                    break;
                case "connected":
                    return tool;
                case "error":
                    Assert.Fail(message.GetRawText());
                    break;
            }
        }
    }

    private static async Task<JsonElement> NextOfAsync(SessionClient client, string type)
    {
        while (true)
        {
            if (client.Received.FirstOrDefault(m => m.GetProperty("type").GetString() == type) is { ValueKind: JsonValueKind.Object } kept)
            {
                client.Received.Remove(kept);
                return kept;
            }

            var message = await client.NextAsync();
            if (message.GetProperty("type").GetString() == type)
            {
                return message;
            }
        }
    }

    private async Task WaitForAsync(string process)
    {
        for (var i = 0; i < 40 && !await RunningAsync(process); i++)
        {
            await Task.Delay(250, Token);
        }

        Assert.True(await RunningAsync(process), $"{process} didn't start.");
    }

    private async Task GoneAsync(string process)
    {
        for (var i = 0; i < 40 && await RunningAsync(process); i++)
        {
            await Task.Delay(250, Token);
        }

        Assert.False(await RunningAsync(process), $"{process} is still running.");
    }

    /// <summary>Whether a process is running; the pattern's first letter in brackets keeps pgrep from finding its own shell.</summary>
    private async Task<bool> RunningAsync(string process) =>
        (await linux.ExecAsync($"pgrep -f '[{process[0]}]{process[1..]}' > /dev/null && echo yes || echo no")).Trim() == "yes";

    private async Task<Guid> CreateUserAsync(string userName)
    {
        using var admin = await _server.SignedInClientAsync(Token);
        using var created = await admin.SendAsync(HttpMethod.Post, "/api/users", new { userName, email = $"{userName}@nkeeper.test", password = BobPassword, role = "user", mustChangePassword = false }, Token);
        Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync(Token));
        return (await created.Content.ReadFromJsonAsync<JsonElement>(Token)).GetProperty("id").GetGuid();
    }

    private async Task<string> SignInAsync(string userName, string password)
    {
        using var client = _server.CreateClient();
        using var login = await client.SendAsync(HttpMethod.Post, "/api/auth/login", new { userNameOrEmail = userName, password, rememberMe = false }, Token);
        Assert.True(login.IsSuccessStatusCode, await login.Content.ReadAsStringAsync(Token));
        return string.Join("; ", login.Headers.GetValues("Set-Cookie").Select(c => c.Split(';')[0]));
    }

    private static async Task<HttpResponseMessage> GetAsync(HttpClient http, string url, string cookie)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(url, UriKind.Relative));
        request.Headers.Add("Cookie", cookie);
        return await http.SendAsync(request, Token);
    }
}
