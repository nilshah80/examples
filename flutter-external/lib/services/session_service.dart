import 'dart:convert';

import 'package:http/http.dart' as http;

import '../config.dart';
import '../models/api_models.dart';
import '../models/session_context.dart';
import 'crypto_service.dart';

/// ECDH session management.
/// Step 1: Anonymous session init (30 min TTL).
/// Step 4: Authenticated session refresh with Bearer + X-Subject (1 hr TTL).
class SessionService {
  final CryptoService _crypto;

  SessionService(this._crypto);

  /// Step 1: Anonymous ECDH session initialization.
  Future<SessionContext> initSession() async {
    final keyPair = await _crypto.generateEcdhKeyPair();
    final pubKeyBytes = await _crypto.exportPublicKey(keyPair);
    final nonce = _crypto.generateNonce();
    final ts = DateTime.now().millisecondsSinceEpoch.toString();

    final body = jsonEncode(
      SessionInitRequest(clientPublicKey: _crypto.toBase64(pubKeyBytes)).toJson(),
    );

    final response = await http.post(
      Uri.parse('${AppConfig.sidecarUrl}/api/v1/session/init'),
      headers: {
        'Content-Type': 'application/json',
        'X-Idempotency-Key': '$ts.$nonce',
        'X-ClientId': AppConfig.clientId,
      },
      body: body,
    );

    if (response.statusCode != 200) {
      throw Exception(
        'Session init failed: HTTP ${response.statusCode} — ${response.body}',
      );
    }

    final data = SessionInitResponse.fromJson(
      jsonDecode(response.body) as Map<String, dynamic>,
    );

    return _deriveSession(keyPair, data, authenticated: false);
  }

  /// Step 4: Authenticated session refresh.
  Future<SessionContext> refreshSession(
    String accessToken,
    String subject,
    SessionContext? oldSession,
  ) async {
    final keyPair = await _crypto.generateEcdhKeyPair();
    final pubKeyBytes = await _crypto.exportPublicKey(keyPair);
    final nonce = _crypto.generateNonce();
    final ts = DateTime.now().millisecondsSinceEpoch.toString();

    final body = jsonEncode(
      SessionInitRequest(clientPublicKey: _crypto.toBase64(pubKeyBytes)).toJson(),
    );

    final response = await http.post(
      Uri.parse('${AppConfig.sidecarUrl}/api/v1/session/init'),
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer $accessToken',
        'X-Subject': subject,
        'X-Idempotency-Key': '$ts.$nonce',
        'X-ClientId': AppConfig.clientId,
      },
      body: body,
    );

    if (response.statusCode != 200) {
      throw Exception(
        'Session refresh failed: HTTP ${response.statusCode} — ${response.body}',
      );
    }

    // Zeroize old session key
    oldSession?.zeroize();

    final data = SessionInitResponse.fromJson(
      jsonDecode(response.body) as Map<String, dynamic>,
    );

    return _deriveSession(keyPair, data, authenticated: true);
  }

  Future<SessionContext> _deriveSession(
    EcdhKeyPair keyPair,
    SessionInitResponse data, {
    required bool authenticated,
  }) async {
    final shared = await _crypto.computeSharedSecret(
      keyPair,
      data.serverPublicKey,
    );

    final sessionKey = await _crypto.deriveSessionKey(
      shared,
      data.sessionId,
      AppConfig.clientId,
    );

    return SessionContext(
      sessionId: data.sessionId,
      sessionKey: sessionKey,
      kid: 'session:${data.sessionId}',
      clientId: AppConfig.clientId,
      authenticated: authenticated,
      expiresInSec: data.expiresInSec,
    );
  }
}
