namespace IdentityExample.Models;

/// <summary>
/// Result of a single step in the 6-step OAuth2 journey.
/// </summary>
public sealed record StepResult(
    int Step,
    string Name,
    Dictionary<string, string> RequestHeaders,
    string RequestBodyPlaintext,
    string RequestBodyEncrypted,
    Dictionary<string, string> ResponseHeaders,
    string ResponseBodyEncrypted,
    string ResponseBodyDecrypted,
    long DurationMs,
    bool Success,
    string? Error
);
