/// Request body for POST /api/v1/session/init.
class SessionInitRequest {
  final String clientPublicKey;

  SessionInitRequest({required this.clientPublicKey});

  Map<String, dynamic> toJson() => {'clientPublicKey': clientPublicKey};
}

/// Response body from POST /api/v1/session/init.
class SessionInitResponse {
  final String sessionId;
  final String serverPublicKey;
  final String? encAlg;
  final int expiresInSec;

  SessionInitResponse({
    required this.sessionId,
    required this.serverPublicKey,
    this.encAlg,
    required this.expiresInSec,
  });

  factory SessionInitResponse.fromJson(Map<String, dynamic> json) {
    return SessionInitResponse(
      sessionId: json['sessionId'] as String,
      serverPublicKey: json['serverPublicKey'] as String,
      encAlg: json['encAlg'] as String?,
      expiresInSec: json['expiresInSec'] as int,
    );
  }
}

/// Encrypted payload wrapper for request/response bodies.
class EncryptedPayload {
  final String payload;

  EncryptedPayload({required this.payload});

  Map<String, dynamic> toJson() => {'payload': payload};

  factory EncryptedPayload.fromJson(Map<String, dynamic> json) {
    return EncryptedPayload(payload: json['payload'] as String);
  }
}
