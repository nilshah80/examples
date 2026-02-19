using System.Text.Json.Serialization;

namespace IdentityExample.Models;

public sealed record SessionInitRequest(
    [property: JsonPropertyName("clientPublicKey")] string ClientPublicKey
);

public sealed record SessionInitResponse(
    [property: JsonPropertyName("sessionId")] string SessionId,
    [property: JsonPropertyName("serverPublicKey")] string ServerPublicKey,
    [property: JsonPropertyName("encAlg")] string? EncAlg,
    [property: JsonPropertyName("expiresInSec")] int ExpiresInSec
);

public sealed record EncryptedPayload(
    [property: JsonPropertyName("payload")] string Payload
);
