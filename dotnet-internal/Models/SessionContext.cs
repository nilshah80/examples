using System.Security.Cryptography;

namespace IdentityExample.Models;

/// <summary>
/// Holds the ECDH-derived session state after key exchange.
/// </summary>
public sealed class SessionContext
{
    public string SessionId { get; }
    public byte[] SessionKey { get; private set; }
    public string Kid { get; }
    public string ClientId { get; }
    public bool Authenticated { get; }
    public int ExpiresInSec { get; }

    public SessionContext(string sessionId, byte[] sessionKey, string kid,
                          string clientId, bool authenticated, int expiresInSec)
    {
        SessionId = sessionId;
        SessionKey = sessionKey;
        Kid = kid;
        ClientId = clientId;
        Authenticated = authenticated;
        ExpiresInSec = expiresInSec;
    }

    public void Zeroize()
    {
        if (SessionKey != null)
        {
            CryptographicOperations.ZeroMemory(SessionKey);
            SessionKey = null!;
        }
    }
}
