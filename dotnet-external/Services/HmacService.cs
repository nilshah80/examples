using System.Security.Cryptography;
using System.Text;

namespace IdentityExample.Services;

/// <summary>
/// HMAC-SHA256 signature computation for external client authentication.
///
/// Signature format:
///   bodyHash     = SHA-256(plaintextBody).hex()
///   stringToSign = "METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_HASH"
///   signature    = HMAC-SHA256(secret, stringToSign).hex()
///
/// IMPORTANT: HMAC is computed over the PLAINTEXT body (before GCM encryption).
/// </summary>
public sealed class HmacService
{
    public string ComputeSignature(string method, string path, string timestamp,
                                    string nonce, string body, string secret)
    {
        // SHA-256 hash of the plaintext body → hex
        var bodyHash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant();

        // Build string-to-sign
        var stringToSign = $"{method.ToUpperInvariant()}\n{path}\n{timestamp}\n{nonce}\n{bodyHash}";

        // HMAC-SHA256(secret, stringToSign) → hex
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var signature = hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));
        return Convert.ToHexString(signature).ToLowerInvariant();
    }
}
