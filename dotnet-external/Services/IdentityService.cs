using System.Diagnostics;
using System.Text;
using System.Text.Json;
using IdentityExample.Models;

namespace IdentityExample.Services;

/// <summary>
/// Token operations for external client.
/// Step 2: HMAC-SHA256 (X-Signature) instead of Basic Auth.
/// Steps 3-6: Bearer + GCM (same as internal).
/// </summary>
public sealed class IdentityService
{
    private readonly CryptoService _crypto;
    private readonly HmacService _hmac;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly string _sidecarUrl;
    private readonly string _clientId;
    private readonly string _clientSecret;

    public IdentityService(CryptoService crypto, HmacService hmac,
                           IHttpClientFactory httpClientFactory, IConfiguration config)
    {
        _crypto = crypto;
        _hmac = hmac;
        _httpClientFactory = httpClientFactory;
        _sidecarUrl = config["Sidecar:Url"] ?? "http://localhost:8141";
        _clientId = config["Client:Id"] ?? "external-partner-test";
        _clientSecret = config["Client:Secret"] ?? "";
    }

    /// <summary>Step 2: Issue tokens with HMAC-SHA256 + GCM.</summary>
    public async Task<StepResult> IssueTokenAsync(SessionContext session, string plaintext)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var nonce = _crypto.GenerateNonce();
            var ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
            var aad = _crypto.BuildAad(ts, nonce, session.Kid, session.ClientId);
            var encrypted = _crypto.AesGcmEncrypt(session.SessionKey, Encoding.UTF8.GetBytes(plaintext), aad);
            var payload = _crypto.ToBase64(encrypted);

            // HMAC over PLAINTEXT body (before encryption)
            var signature = _hmac.ComputeSignature("POST", "/api/v1/token/issue",
                ts, nonce, plaintext, _clientSecret);

            var headers = new Dictionary<string, string>
            {
                ["Content-Type"] = "application/json",
                ["X-Kid"] = session.Kid,
                ["X-ClientId"] = session.ClientId,
                ["X-Idempotency-Key"] = $"{ts}.{nonce}",
                ["X-Signature"] = signature
            };

            var (respHeaders, respEncrypted, decrypted) = await SendEncrypted(
                "/api/v1/token/issue", payload, headers, session);

            sw.Stop();
            return new StepResult(2, "Token Issue (HMAC + GCM)", headers, plaintext, payload,
                respHeaders, respEncrypted, decrypted, sw.ElapsedMilliseconds, true, null);
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new StepResult(2, "Token Issue (HMAC + GCM)",
                new Dictionary<string, string>(), plaintext, "",
                new Dictionary<string, string>(), "", "",
                sw.ElapsedMilliseconds, false, ex.Message);
        }
    }

    /// <summary>Step 3: Introspect token (Bearer + GCM).</summary>
    public Task<StepResult> IntrospectTokenAsync(SessionContext session, string plaintext, string accessToken)
        => PostBearerEncrypted("/api/v1/introspect", session, plaintext, accessToken,
            3, "Token Introspection (Bearer + GCM)");

    /// <summary>Step 5: Refresh tokens (Bearer + GCM).</summary>
    public Task<StepResult> RefreshTokenAsync(SessionContext session, string plaintext, string accessToken)
        => PostBearerEncrypted("/api/v1/token", session, plaintext, accessToken,
            5, "Token Refresh (Bearer + GCM)");

    /// <summary>Step 6: Revoke token (Bearer + GCM).</summary>
    public Task<StepResult> RevokeTokenAsync(SessionContext session, string plaintext, string accessToken)
        => PostBearerEncrypted("/api/v1/revoke", session, plaintext, accessToken,
            6, "Token Revocation (Bearer + GCM)");

    private async Task<StepResult> PostBearerEncrypted(
        string fullPath, SessionContext session, string plaintext,
        string accessToken, int stepNum, string stepName)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var nonce = _crypto.GenerateNonce();
            var ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
            var aad = _crypto.BuildAad(ts, nonce, session.Kid, session.ClientId);
            var encrypted = _crypto.AesGcmEncrypt(session.SessionKey, Encoding.UTF8.GetBytes(plaintext), aad);
            var payload = _crypto.ToBase64(encrypted);

            var headers = new Dictionary<string, string>
            {
                ["Content-Type"] = "application/json",
                ["Authorization"] = $"Bearer {accessToken}",
                ["X-Kid"] = session.Kid,
                ["X-Idempotency-Key"] = $"{ts}.{nonce}",
                ["X-ClientId"] = session.ClientId
            };

            var (respHeaders, respEncrypted, decrypted) = await SendEncrypted(
                fullPath, payload, headers, session);

            sw.Stop();
            return new StepResult(stepNum, stepName, headers, plaintext, payload,
                respHeaders, respEncrypted, decrypted, sw.ElapsedMilliseconds, true, null);
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new StepResult(stepNum, stepName,
                new Dictionary<string, string>(), plaintext, "",
                new Dictionary<string, string>(), "", "",
                sw.ElapsedMilliseconds, false, ex.Message);
        }
    }

    private async Task<(Dictionary<string, string> respHeaders, string respEncrypted, string decrypted)>
        SendEncrypted(string fullPath, string payload, Dictionary<string, string> headers, SessionContext session)
    {
        var requestBody = JsonSerializer.Serialize(new EncryptedPayload(payload));
        using var client = _httpClientFactory.CreateClient("sidecar");
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_sidecarUrl}{fullPath}");
        request.Content = new StringContent(requestBody, Encoding.UTF8, "application/json");
        foreach (var (k, v) in headers)
        {
            if (k.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)) continue;
            request.Headers.TryAddWithoutValidation(k, v);
        }

        var response = await client.SendAsync(request);
        var responseBodyStr = await response.Content.ReadAsStringAsync();

        var respHeaders = new Dictionary<string, string>();
        foreach (var key in new[] { "x-kid", "x-idempotency-key", "content-type" })
        {
            if (response.Headers.TryGetValues(key, out var vals))
                respHeaders[key] = vals.First();
            else if (response.Content.Headers.TryGetValues(key, out var cVals))
                respHeaders[key] = cVals.First();
        }

        if (!response.IsSuccessStatusCode)
            throw new Exception($"HTTP {(int)response.StatusCode}: {responseBodyStr}");

        // Decrypt response
        var respKid = respHeaders.GetValueOrDefault("x-kid");
        var respIdempKey = respHeaders.GetValueOrDefault("x-idempotency-key");

        if (respKid != null && respIdempKey != null)
        {
            var parts = respIdempKey.Split('.');
            var respAad = _crypto.BuildAad(parts[0], parts[1], respKid, session.ClientId);
            var resBody = JsonSerializer.Deserialize<EncryptedPayload>(responseBodyStr)!;
            var decryptedBytes = _crypto.AesGcmDecrypt(session.SessionKey, respAad, _crypto.FromBase64(resBody.Payload));
            return (respHeaders, resBody.Payload, Encoding.UTF8.GetString(decryptedBytes));
        }

        return (respHeaders, "", responseBodyStr);
    }
}
