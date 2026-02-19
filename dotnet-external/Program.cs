using System.Text.Json;
using IdentityExample.Models;
using IdentityExample.Services;

var builder = WebApplication.CreateBuilder(args);

// Load .env file (optional — won't fail if missing)
var envPath = Path.Combine(Directory.GetCurrentDirectory(), ".env");
if (File.Exists(envPath))
{
    var envVars = new Dictionary<string, string>();
    foreach (var line in File.ReadAllLines(envPath))
    {
        var trimmed = line.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith('#')) continue;
        var idx = trimmed.IndexOf('=');
        if (idx <= 0) continue;
        envVars[trimmed[..idx].Trim()] = trimmed[(idx + 1)..].Trim();
    }

    // Map standard env var names → ASP.NET nested config keys
    var mapping = new Dictionary<string, string>
    {
        ["CLIENT_ID"] = "Client:Id",
        ["CLIENT_SECRET"] = "Client:Secret",
        ["SUBJECT"] = "Client:Subject",
        ["PORT"] = "Server:Port",
        ["SIDECAR_URL"] = "Sidecar:Url",
    };

    var mapped = new Dictionary<string, string?>();
    foreach (var (envKey, configKey) in mapping)
        if (envVars.TryGetValue(envKey, out var val))
            mapped[configKey] = val;

    if (mapped.Count > 0)
        builder.Configuration.AddInMemoryCollection(mapped);
}

// Register services
builder.Services.AddSingleton<CryptoService>();
builder.Services.AddSingleton<HmacService>();
builder.Services.AddSingleton<SessionService>();
builder.Services.AddSingleton<IdentityService>();
builder.Services.AddSingleton<JourneyState>();
builder.Services.AddHttpClient("sidecar", client =>
{
    client.Timeout = TimeSpan.FromSeconds(30);
});

var app = builder.Build();

// ── CLI mode: dotnet run -- --cli ───────────────────
if (args.Contains("--cli"))
{
    await RunCli(app.Services, app.Configuration);
    return;
}

// ── Web server mode ─────────────────────────────────
app.UseDefaultFiles();
app.UseStaticFiles();

var subject = app.Configuration["Client:Subject"] ?? "hmac-user";

// ── Step API endpoints (all crypto in .NET) ─────────

app.MapPost("/steps/1", async (SessionService sessionSvc, JourneyState state) =>
{
    var sw = System.Diagnostics.Stopwatch.StartNew();
    try
    {
        state.Session = await sessionSvc.InitSessionAsync();
        state.AccessToken = "";
        state.RefreshToken = "";
        sw.Stop();
        return Results.Ok(new
        {
            step = 1, name = "Session Init (Anonymous ECDH)",
            success = true, durationMs = sw.ElapsedMilliseconds,
            sessionId = state.Session.SessionId, kid = state.Session.Kid,
            authenticated = state.Session.Authenticated,
            expiresInSec = state.Session.ExpiresInSec
        });
    }
    catch (Exception ex)
    {
        sw.Stop();
        return Results.Ok(new
        {
            step = 1, name = "Session Init (Anonymous ECDH)",
            success = false, durationMs = sw.ElapsedMilliseconds,
            sessionId = "", kid = "", authenticated = false, expiresInSec = 0,
            error = ex.Message
        });
    }
});

app.MapPost("/steps/2", async (IdentityService identitySvc, JourneyState state) =>
{
    if (state.Session == null)
        return Results.BadRequest(new { error = "Run step 1 first" });

    var body = JsonSerializer.Serialize(new
    {
        audience = "orders-api",
        scope = "orders.read",
        subject,
        include_refresh_token = true,
        single_session = true,
        custom_claims = new { partner_id = "PARTNER-001", region = "us-east-1" }
    });

    var result = await identitySvc.IssueTokenAsync(state.Session, body);
    if (result.Success)
    {
        var data = JsonDocument.Parse(result.ResponseBodyDecrypted);
        state.AccessToken = data.RootElement.GetProperty("access_token").GetString()!;
        state.RefreshToken = data.RootElement.TryGetProperty("refresh_token", out var rt) ? rt.GetString()! : "";
    }
    return Results.Ok(result);
});

app.MapPost("/steps/3", async (IdentityService identitySvc, JourneyState state) =>
{
    if (state.Session == null || string.IsNullOrEmpty(state.AccessToken))
        return Results.BadRequest(new { error = "Run steps 1-2 first" });

    var body = JsonSerializer.Serialize(new { token = state.AccessToken });
    var result = await identitySvc.IntrospectTokenAsync(state.Session, body, state.AccessToken);
    return Results.Ok(result);
});

app.MapPost("/steps/4", async (SessionService sessionSvc, JourneyState state) =>
{
    if (state.Session == null || string.IsNullOrEmpty(state.AccessToken))
        return Results.BadRequest(new { error = "Run steps 1-3 first" });

    var sw = System.Diagnostics.Stopwatch.StartNew();
    try
    {
        state.Session = await sessionSvc.RefreshSessionAsync(state.AccessToken, subject, state.Session);
        sw.Stop();
        return Results.Ok(new
        {
            step = 4, name = "Session Refresh (Authenticated ECDH)",
            success = true, durationMs = sw.ElapsedMilliseconds,
            sessionId = state.Session.SessionId, kid = state.Session.Kid,
            authenticated = state.Session.Authenticated,
            expiresInSec = state.Session.ExpiresInSec
        });
    }
    catch (Exception ex)
    {
        sw.Stop();
        return Results.Ok(new
        {
            step = 4, name = "Session Refresh (Authenticated ECDH)",
            success = false, durationMs = sw.ElapsedMilliseconds,
            sessionId = "", kid = "", authenticated = false, expiresInSec = 0,
            error = ex.Message
        });
    }
});

app.MapPost("/steps/5", async (IdentityService identitySvc, JourneyState state) =>
{
    if (state.Session == null || string.IsNullOrEmpty(state.AccessToken))
        return Results.BadRequest(new { error = "Run steps 1-4 first" });

    var body = JsonSerializer.Serialize(new
    {
        grant_type = "refresh_token",
        refresh_token = state.RefreshToken
    });

    var result = await identitySvc.RefreshTokenAsync(state.Session, body, state.AccessToken);
    if (result.Success)
    {
        var data = JsonDocument.Parse(result.ResponseBodyDecrypted);
        state.AccessToken = data.RootElement.GetProperty("access_token").GetString()!;
        state.RefreshToken = data.RootElement.TryGetProperty("refresh_token", out var rt) ? rt.GetString()! : "";
    }
    return Results.Ok(result);
});

app.MapPost("/steps/6", async (IdentityService identitySvc, JourneyState state) =>
{
    if (state.Session == null || string.IsNullOrEmpty(state.AccessToken))
        return Results.BadRequest(new { error = "Run steps 1-5 first" });

    var body = JsonSerializer.Serialize(new
    {
        token = state.RefreshToken,
        token_type_hint = "refresh_token"
    });

    var result = await identitySvc.RevokeTokenAsync(state.Session, body, state.AccessToken);
    return Results.Ok(result);
});

app.MapPost("/steps/reset", (JourneyState state) =>
{
    state.Session?.Zeroize();
    state.Session = null;
    state.AccessToken = "";
    state.RefreshToken = "";
    return Results.Ok(new { success = true });
});

var port = app.Configuration.GetValue("Server:Port", 3501);
app.Urls.Add($"http://localhost:{port}");

Console.WriteLine();
Console.WriteLine("  Identity Service — External Client Example (.NET 8)");
Console.WriteLine($"  Web UI:  http://localhost:{port}");
Console.WriteLine($"  API:     /steps/1..6 → .NET crypto → Sidecar");
Console.WriteLine($"  Auth:    HMAC-SHA256");
Console.WriteLine();

app.Run();
return;

// ── CLI Runner ──────────────────────────────────────

static async Task RunCli(IServiceProvider services, IConfiguration config)
{
    const string RESET = "\x1b[0m";
    const string BOLD = "\x1b[1m";
    const string DIM = "\x1b[2m";
    const string AMBER = "\x1b[33m";
    const string GREEN = "\x1b[32m";
    const string CYAN = "\x1b[36m";
    const string YELLOW = "\x1b[33m";

    var sessionSvc = services.GetRequiredService<SessionService>();
    var identitySvc = services.GetRequiredService<IdentityService>();
    var subject = config["Client:Subject"] ?? "hmac-user";
    var clientId = config["Client:Id"] ?? "external-partner-test";

    Console.WriteLine();
    Console.WriteLine($"{AMBER}{BOLD}  ╔══════════════════════════════════════════════════╗{RESET}");
    Console.WriteLine($"{AMBER}{BOLD}  ║  Identity Service — External Client (.NET 8)     ║{RESET}");
    Console.WriteLine($"{AMBER}{BOLD}  ║  Auth: HMAC-SHA256 + AES-256-GCM                 ║{RESET}");
    Console.WriteLine($"{AMBER}{BOLD}  ║  Client: {clientId,-40} ║{RESET}");
    Console.WriteLine($"{AMBER}{BOLD}  ╚══════════════════════════════════════════════════╝{RESET}");
    Console.WriteLine();

    // Step 1: Session Init
    PrintStep(1, "Session Init (Anonymous ECDH)");
    var session = await sessionSvc.InitSessionAsync();
    Console.WriteLine($"{GREEN}    ✓ Session established{RESET}");
    Console.WriteLine($"{DIM}    SessionId: {session.SessionId}{RESET}");
    Console.WriteLine($"{DIM}    Kid:       {session.Kid}{RESET}");
    Console.WriteLine($"{DIM}    TTL:       {session.ExpiresInSec}s ({(session.Authenticated ? "authenticated" : "anonymous")}){RESET}");
    Console.WriteLine();

    // Step 2: Token Issue (HMAC + GCM)
    PrintStep(2, "Token Issue (HMAC-SHA256 + GCM)");
    var issueBody = JsonSerializer.Serialize(new
    {
        audience = "orders-api",
        scope = "orders.read",
        subject,
        include_refresh_token = true,
        single_session = true,
        custom_claims = new { partner_id = "PARTNER-001", region = "us-east-1" }
    });
    var issueResult = await identitySvc.IssueTokenAsync(session, issueBody);
    PrintResult(issueResult);
    var issueData = JsonDocument.Parse(issueResult.ResponseBodyDecrypted);
    var accessToken = issueData.RootElement.GetProperty("access_token").GetString()!;
    var refreshToken = issueData.RootElement.TryGetProperty("refresh_token", out var rt) ? rt.GetString()! : "";

    // Step 3: Token Introspection
    PrintStep(3, "Token Introspection (Bearer + GCM)");
    var introBody = JsonSerializer.Serialize(new { token = accessToken });
    var introResult = await identitySvc.IntrospectTokenAsync(session, introBody, accessToken);
    PrintResult(introResult);

    // Step 4: Session Refresh
    PrintStep(4, "Session Refresh (Authenticated ECDH)");
    session = await sessionSvc.RefreshSessionAsync(accessToken, subject, session);
    Console.WriteLine($"{GREEN}    ✓ Session refreshed{RESET}");
    Console.WriteLine($"{DIM}    SessionId: {session.SessionId}{RESET}");
    Console.WriteLine($"{DIM}    TTL:       {session.ExpiresInSec}s (authenticated){RESET}");
    Console.WriteLine();

    // Step 5: Token Refresh
    PrintStep(5, "Token Refresh (Bearer + GCM)");
    var refreshBody = JsonSerializer.Serialize(new
    {
        grant_type = "refresh_token",
        refresh_token = refreshToken
    });
    var refreshResult = await identitySvc.RefreshTokenAsync(session, refreshBody, accessToken);
    PrintResult(refreshResult);
    var refreshData = JsonDocument.Parse(refreshResult.ResponseBodyDecrypted);
    accessToken = refreshData.RootElement.GetProperty("access_token").GetString()!;
    refreshToken = refreshData.RootElement.TryGetProperty("refresh_token", out var rt2) ? rt2.GetString()! : "";

    // Step 6: Token Revocation
    PrintStep(6, "Token Revocation (Bearer + GCM)");
    var revokeBody = JsonSerializer.Serialize(new
    {
        token = refreshToken,
        token_type_hint = "refresh_token"
    });
    var revokeResult = await identitySvc.RevokeTokenAsync(session, revokeBody, accessToken);
    PrintResult(revokeResult);

    // Cleanup
    session.Zeroize();
    Console.WriteLine($"{GREEN}{BOLD}  All 6 steps completed successfully!{RESET}");
    Console.WriteLine();

    return;

    void PrintStep(int n, string name)
    {
        Console.WriteLine($"{CYAN}{BOLD}  ── Step {n}: {name} ──{RESET}");
    }

    void PrintResult(StepResult r)
    {
        var status = r.Success ? $"{GREEN}✓ Success" : $"\x1b[31m✗ Failed";
        Console.WriteLine($"    {status} ({r.DurationMs}ms){RESET}");
        Console.WriteLine($"{YELLOW}    Request Body (plaintext):{RESET}");
        Console.WriteLine($"{DIM}      {Truncate(r.RequestBodyPlaintext, 200)}{RESET}");
        Console.WriteLine($"{YELLOW}    Response Body (decrypted):{RESET}");
        Console.WriteLine($"{DIM}      {Truncate(r.ResponseBodyDecrypted, 200)}{RESET}");
        if (!r.Success && r.Error != null)
            Console.WriteLine($"\x1b[31m    Error: {r.Error}{RESET}");
        Console.WriteLine();
    }

    string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) ? "(empty)" : s.Length > max ? s[..max] + "..." : s;
}

// ── Journey State (single-user demo) ────────────────

/// <summary>In-memory state for the 6-step Web UI journey.</summary>
public class JourneyState
{
    public SessionContext? Session { get; set; }
    public string AccessToken { get; set; } = "";
    public string RefreshToken { get; set; } = "";
}
