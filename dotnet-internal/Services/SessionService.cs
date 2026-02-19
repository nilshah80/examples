using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IdentityExample.Models;

namespace IdentityExample.Services;

/// <summary>
/// ECDH session management.
/// Step 1: Anonymous session init (30 min TTL).
/// Step 4: Authenticated session refresh with Bearer + X-Subject (1 hr TTL).
/// </summary>
public sealed class SessionService
{
    private readonly CryptoService _crypto;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly string _clientId;
    private readonly string _sidecarUrl;

    public SessionService(CryptoService crypto, IHttpClientFactory httpClientFactory,
                          IConfiguration config)
    {
        _crypto = crypto;
        _httpClientFactory = httpClientFactory;
        _clientId = config["Client:Id"] ?? "dev-client";
        _sidecarUrl = config["Sidecar:Url"] ?? "http://localhost:8141";
    }

    /// <summary>Step 1: Anonymous ECDH session initialization.</summary>
    public async Task<SessionContext> InitSessionAsync()
    {
        using var ecdh = _crypto.GenerateEcdhKeyPair();
        var pubKeyBytes = _crypto.ExportPublicKey(ecdh);
        var nonce = _crypto.GenerateNonce();
        var ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();

        var body = JsonSerializer.Serialize(new SessionInitRequest(_crypto.ToBase64(pubKeyBytes)));

        using var client = _httpClientFactory.CreateClient("sidecar");
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_sidecarUrl}/api/v1/session/init");
        request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        request.Headers.Add("X-Idempotency-Key", $"{ts}.{nonce}");
        request.Headers.Add("X-ClientId", _clientId);

        var response = await client.SendAsync(request);
        var responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new Exception($"Session init failed: HTTP {(int)response.StatusCode} — {responseBody}");

        var data = JsonSerializer.Deserialize<SessionInitResponse>(responseBody)!;
        return DeriveSession(ecdh, data, authenticated: false);
    }

    /// <summary>Step 4: Authenticated session refresh.</summary>
    public async Task<SessionContext> RefreshSessionAsync(
        string accessToken, string subject, SessionContext? oldSession)
    {
        using var ecdh = _crypto.GenerateEcdhKeyPair();
        var pubKeyBytes = _crypto.ExportPublicKey(ecdh);
        var nonce = _crypto.GenerateNonce();
        var ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();

        var body = JsonSerializer.Serialize(new SessionInitRequest(_crypto.ToBase64(pubKeyBytes)));

        using var client = _httpClientFactory.CreateClient("sidecar");
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_sidecarUrl}/api/v1/session/init");
        request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        request.Headers.Add("Authorization", $"Bearer {accessToken}");
        request.Headers.Add("X-Subject", subject);
        request.Headers.Add("X-Idempotency-Key", $"{ts}.{nonce}");
        request.Headers.Add("X-ClientId", _clientId);

        var response = await client.SendAsync(request);
        var responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new Exception($"Session refresh failed: HTTP {(int)response.StatusCode} — {responseBody}");

        // Zeroize old session key
        oldSession?.Zeroize();

        var data = JsonSerializer.Deserialize<SessionInitResponse>(responseBody)!;
        return DeriveSession(ecdh, data, authenticated: true);
    }

    private SessionContext DeriveSession(ECDiffieHellman ecdh, SessionInitResponse data, bool authenticated)
    {
        var serverPubBytes = _crypto.FromBase64(data.ServerPublicKey);
        var shared = _crypto.ComputeSharedSecret(ecdh, serverPubBytes);

        var salt = Encoding.UTF8.GetBytes(data.SessionId);
        var info = Encoding.UTF8.GetBytes($"SESSION|A256GCM|{_clientId}");
        var sessionKey = _crypto.Hkdf(shared, salt, info, 32);

        CryptographicOperations.ZeroMemory(shared);

        return new SessionContext(
            data.SessionId, sessionKey, $"session:{data.SessionId}",
            _clientId, authenticated, data.ExpiresInSec);
    }
}
