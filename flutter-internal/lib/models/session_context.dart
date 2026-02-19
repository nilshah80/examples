import 'dart:typed_data';

/// In-memory ECDH-derived session state.
class SessionContext {
  final String sessionId;
  final Uint8List sessionKey; // 32-byte AES-256 key
  final String kid;
  final String clientId;
  final bool authenticated;
  final int expiresInSec;

  SessionContext({
    required this.sessionId,
    required this.sessionKey,
    required this.kid,
    required this.clientId,
    required this.authenticated,
    required this.expiresInSec,
  });

  /// Securely zero the session key in memory.
  void zeroize() {
    for (var i = 0; i < sessionKey.length; i++) {
      sessionKey[i] = 0;
    }
  }
}
