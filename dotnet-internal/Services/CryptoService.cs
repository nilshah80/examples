using System.Security.Cryptography;
using System.Text;

namespace IdentityExample.Services;

/// <summary>
/// Cryptographic operations: ECDH P-256, HKDF-SHA256, AES-256-GCM.
/// All APIs are built into .NET 8 — zero NuGet dependencies.
/// </summary>
public sealed class CryptoService
{
    // ── Base64 ──────────────────────────────────────

    public string ToBase64(byte[] data) => Convert.ToBase64String(data);
    public byte[] FromBase64(string b64) => Convert.FromBase64String(b64);

    // ── Nonce ───────────────────────────────────────

    public string GenerateNonce() => Guid.NewGuid().ToString();

    // ── ECDH P-256 ─────────────────────────────────

    /// <summary>Generate an ECDH P-256 keypair.</summary>
    public ECDiffieHellman GenerateEcdhKeyPair()
        => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>
    /// Export EC public key as 65-byte uncompressed: 0x04 || X(32) || Y(32).
    /// </summary>
    public byte[] ExportPublicKey(ECDiffieHellman ecdh)
    {
        var p = ecdh.ExportParameters(includePrivateParameters: false);
        var result = new byte[65];
        result[0] = 0x04;
        Buffer.BlockCopy(PadTo32(p.Q.X!), 0, result, 1, 32);
        Buffer.BlockCopy(PadTo32(p.Q.Y!), 0, result, 33, 32);
        return result;
    }

    /// <summary>
    /// Compute ECDH shared secret from our private key and peer's 65-byte
    /// uncompressed public key.
    /// </summary>
    public byte[] ComputeSharedSecret(ECDiffieHellman ecdh, byte[] peerPublicKeyBytes)
    {
        if (peerPublicKeyBytes.Length != 65 || peerPublicKeyBytes[0] != 0x04)
            throw new ArgumentException("Invalid uncompressed EC public key (expected 65 bytes starting with 0x04)");

        var peerParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = peerPublicKeyBytes.AsSpan(1, 32).ToArray(),
                Y = peerPublicKeyBytes.AsSpan(33, 32).ToArray()
            }
        };

        using var peerKey = ECDiffieHellman.Create(peerParams);
        return ecdh.DeriveRawSecretAgreement(peerKey.PublicKey);
    }

    // ── HKDF-SHA256 ────────────────────────────────

    /// <summary>HKDF-SHA256 key derivation (built-in since .NET 5).</summary>
    public byte[] Hkdf(byte[] ikm, byte[] salt, byte[] info, int length)
        => HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, length, salt, info);

    // ── AES-256-GCM ────────────────────────────────

    /// <summary>
    /// AES-256-GCM encrypt.
    /// Returns: IV(12) || ciphertext || tag(16).
    /// </summary>
    public byte[] AesGcmEncrypt(byte[] key, byte[] plaintext, byte[] aad)
    {
        var iv = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];

        using var aesGcm = new AesGcm(key, tagSizeInBytes: 16);
        aesGcm.Encrypt(iv, plaintext, ciphertext, tag, aad);

        var result = new byte[12 + ciphertext.Length + 16];
        Buffer.BlockCopy(iv, 0, result, 0, 12);
        Buffer.BlockCopy(ciphertext, 0, result, 12, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, 12 + ciphertext.Length, 16);
        return result;
    }

    /// <summary>
    /// AES-256-GCM decrypt.
    /// Input: IV(12) || ciphertext || tag(16).
    /// </summary>
    public byte[] AesGcmDecrypt(byte[] key, byte[] aad, byte[] encrypted)
    {
        var iv = encrypted.AsSpan(0, 12);
        var ciphertext = encrypted.AsSpan(12, encrypted.Length - 28);
        var tag = encrypted.AsSpan(encrypted.Length - 16, 16);
        var plaintext = new byte[ciphertext.Length];

        using var aesGcm = new AesGcm(key, tagSizeInBytes: 16);
        aesGcm.Decrypt(iv, ciphertext, tag, plaintext, aad);
        return plaintext;
    }

    // ── AAD ─────────────────────────────────────────

    /// <summary>Build AAD: "timestamp|nonce|kid|clientId" as UTF-8 bytes.</summary>
    public byte[] BuildAad(string timestamp, string nonce, string kid, string clientId)
        => Encoding.UTF8.GetBytes($"{timestamp}|{nonce}|{kid}|{clientId}");

    // ── Helpers ─────────────────────────────────────

    /// <summary>Left-pad byte array to exactly 32 bytes (EC coordinate padding).</summary>
    private static byte[] PadTo32(byte[] data)
    {
        if (data.Length == 32) return data;
        if (data.Length > 32) return data.AsSpan(data.Length - 32, 32).ToArray();
        var padded = new byte[32];
        Buffer.BlockCopy(data, 0, padded, 32 - data.Length, data.Length);
        return padded;
    }
}
