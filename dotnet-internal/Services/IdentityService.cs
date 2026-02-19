using System.Diagnostics;
using System.Text;
using System.Text.Json;
using IdentityExample.Models;

namespace IdentityExample.Services;

/// <summary>
/// Token operations with AES-256-GCM encryption.
/// Internal client: Basic Auth for token issue, Bearer for steps 3/5/6.
/// </summary>
public class IdentityService
{
    protected readonly CryptoService Crypto;
    protected readonly IHttpClientFactory HttpClientFactory;
    protected readonly string SidecarUrl;
    protected readonly string ClientId;
    protected readonly string ClientSecret;

    public IdentityService(CryptoService crypto, IHttpClientFactory httpClientFactory,
                           IConfiguration config)
    {
        Crypto = crypto;
        HttpClientFactory = httpClientFactory;
        SidecarUrl = config["Sidecar:Url"] ?? "http://localhost:8141";
        ClientId = config["Client:Id"] ?? "dev-client";
        ClientSecret = config["Client:Secret"] ?? "";
    }

    private string BasicAuth
        => $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{ClientId}:{ClientSecret}"))}";

    /// <summary>Step 2: Issue tokens (Basic Auth + GCM).</summary>
    public virtual Task<StepResult> IssueTokenAsync(SessionContext session, string plaintext)
        => PostEncryptedAsync("/v1/token/issue", session, plaintext,
            new Dictionary<string, string> { ["Authorization"] = BasicAuth },
            2, "Token Issue (Basic Auth + GCM)");

    /// <summary>Step 3: Introspect token (Bearer + GCM).</summary>
    public Task<StepResult> IntrospectTokenAsync(SessionContext session, string plaintext, string accessToken)
        => PostEncryptedAsync("/v1/introspect", session, plaintext,
            new Dictionary<string, string> { ["Authorization"] = $"Bearer {accessToken}" },
            3, "Token Introspection (Bearer + GCM)");

    /// <summary>Step 5: Refresh tokens (Bearer + GCM).</summary>
    public Task<StepResult> RefreshTokenAsync(SessionContext session, string plaintext, string accessToken)
        => PostEncryptedAsync("/v1/token", session, plaintext,
            new Dictionary<string, string> { ["Authorization"] = $"Bearer {accessToken}" },
            5, "Token Refresh (Bearer + GCM)");

    /// <summary>Step 6: Revoke token (Bearer + GCM).</summary>
    public Task<StepResult> RevokeTokenAsync(SessionContext session, string plaintext, string accessToken)
        => PostEncryptedAsync("/v1/revoke", session, plaintext,
            new Dictionary<string, string> { ["Authorization"] = $"Bearer {accessToken}" },
            6, "Token Revocation (Bearer + GCM)");

    /// <summary>Core: encrypt body → POST → decrypt response.</summary>
    protected async Task<StepResult> PostEncryptedAsync(
        string path, SessionContext session, string plaintext,
        Dictionary<string, string> authHeaders, int stepNum, string stepName)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var nonce = Crypto.GenerateNonce();
            var ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
            var aad = Crypto.BuildAad(ts, nonce, session.Kid, session.ClientId);
            var encrypted = Crypto.AesGcmEncrypt(session.SessionKey, Encoding.UTF8.GetBytes(plaintext), aad);
            var payload = Crypto.ToBase64(encrypted);

            // Build request headers
            var headers = new Dictionary<string, string>
            {
                ["Content-Type"] = "application/json",
                ["X-Kid"] = session.Kid,
                ["X-Idempotency-Key"] = $"{ts}.{nonce}",
                ["X-ClientId"] = session.ClientId
            };
            foreach (var (k, v) in authHeaders) headers[k] = v;

            // Send
            var requestBody = JsonSerializer.Serialize(new EncryptedPayload(payload));
            using var client = HttpClientFactory.CreateClient("sidecar");
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{SidecarUrl}/api{path}");
            request.Content = new StringContent(requestBody, Encoding.UTF8, "application/json");
            foreach (var (k, v) in headers)
            {
                if (k.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)) continue;
                request.Headers.TryAddWithoutValidation(k, v);
            }

            var response = await client.SendAsync(request);
            var responseBodyStr = await response.Content.ReadAsStringAsync();

            // Collect response headers
            var respHeaders = ExtractResponseHeaders(response);

            if (!response.IsSuccessStatusCode)
            {
                sw.Stop();
                return new StepResult(stepNum, stepName, headers, plaintext, payload,
                    respHeaders, "", responseBodyStr, sw.ElapsedMilliseconds, false,
                    $"HTTP {(int)response.StatusCode}: {responseBodyStr}");
            }

            // Decrypt response
            var (respEncrypted, decrypted) = DecryptResponse(responseBodyStr, respHeaders, session);

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

    protected (string encrypted, string decrypted) DecryptResponse(
        string responseBodyStr, Dictionary<string, string> respHeaders, SessionContext session)
    {
        var respKid = respHeaders.GetValueOrDefault("x-kid");
        var respIdempKey = respHeaders.GetValueOrDefault("x-idempotency-key");

        if (respKid != null && respIdempKey != null)
        {
            var parts = respIdempKey.Split('.');
            var respAad = Crypto.BuildAad(parts[0], parts[1], respKid, session.ClientId);
            var resBody = JsonSerializer.Deserialize<EncryptedPayload>(responseBodyStr)!;
            var decryptedBytes = Crypto.AesGcmDecrypt(session.SessionKey, respAad, Crypto.FromBase64(resBody.Payload));
            return (resBody.Payload, Encoding.UTF8.GetString(decryptedBytes));
        }

        return ("", responseBodyStr);
    }

    private static Dictionary<string, string> ExtractResponseHeaders(HttpResponseMessage response)
    {
        var result = new Dictionary<string, string>();
        foreach (var key in new[] { "x-kid", "x-idempotency-key", "content-type" })
        {
            if (response.Headers.TryGetValues(key, out var vals))
                result[key] = vals.First();
            else if (response.Content.Headers.TryGetValues(key, out var cVals))
                result[key] = cVals.First();
        }
        return result;
    }
}
