import 'dart:convert';

import 'package:http/http.dart' as http;

import '../config.dart';
import '../models/api_models.dart';
import '../models/session_context.dart';
import '../models/step_result.dart';
import 'crypto_service.dart';
import 'hmac_service.dart';

/// Token operations with AES-256-GCM encryption.
/// External client: HMAC-SHA256 for token issue, Bearer for steps 3/5/6.
class IdentityService {
  final CryptoService _crypto;
  final HmacService _hmac = HmacService();

  IdentityService(this._crypto);

  /// Step 2: Issue tokens (HMAC-SHA256 + GCM).
  /// HMAC is computed over the PLAINTEXT body (before encryption).
  Future<StepResult> issueToken(SessionContext session, String plaintext) async {
    final sw = Stopwatch()..start();
    try {
      final nonce = _crypto.generateNonce();
      final ts = DateTime.now().millisecondsSinceEpoch.toString();
      final aad = _crypto.buildAad(ts, nonce, session.kid, session.clientId);

      // Compute HMAC over plaintext body BEFORE encryption
      final signature = await _hmac.computeSignature(
        'POST',
        '/api/v1/token/issue',
        ts,
        nonce,
        plaintext,
        AppConfig.clientSecret,
      );

      final encryptedPayload = await _crypto.encrypt(
        plaintext,
        session.sessionKey,
        aad,
      );

      // Build request headers (HMAC instead of Basic Auth)
      final headers = <String, String>{
        'Content-Type': 'application/json',
        'X-Kid': session.kid,
        'X-ClientId': session.clientId,
        'X-Idempotency-Key': '$ts.$nonce',
        'X-Signature': signature,
      };

      final requestBody = jsonEncode(
        EncryptedPayload(payload: encryptedPayload).toJson(),
      );

      final response = await http.post(
        Uri.parse('${AppConfig.sidecarUrl}/api/v1/token/issue'),
        headers: headers,
        body: requestBody,
      );

      final respHeaders = _extractResponseHeaders(response);

      if (response.statusCode != 200) {
        sw.stop();
        return StepResult(
          step: 2,
          name: 'Token Issue (HMAC-SHA256 + GCM)',
          requestHeaders: headers,
          requestBodyPlaintext: plaintext,
          requestBodyEncrypted: encryptedPayload,
          responseHeaders: respHeaders,
          responseBodyDecrypted: response.body,
          durationMs: sw.elapsedMilliseconds,
          error: 'HTTP ${response.statusCode}: ${response.body}',
        );
      }

      final (respEncrypted, decrypted) = await _decryptResponse(
        response.body,
        respHeaders,
        session,
      );

      sw.stop();
      return StepResult(
        step: 2,
        name: 'Token Issue (HMAC-SHA256 + GCM)',
        requestHeaders: headers,
        requestBodyPlaintext: plaintext,
        requestBodyEncrypted: encryptedPayload,
        responseHeaders: respHeaders,
        responseBodyEncrypted: respEncrypted,
        responseBodyDecrypted: decrypted,
        durationMs: sw.elapsedMilliseconds,
        success: true,
      );
    } catch (e) {
      sw.stop();
      return StepResult(
        step: 2,
        name: 'Token Issue (HMAC-SHA256 + GCM)',
        requestBodyPlaintext: plaintext,
        durationMs: sw.elapsedMilliseconds,
        error: e.toString(),
      );
    }
  }

  /// Step 3: Introspect token (Bearer + GCM).
  Future<StepResult> introspectToken(
    SessionContext session,
    String plaintext,
    String accessToken,
  ) {
    return _postEncrypted(
      '/v1/introspect',
      session,
      plaintext,
      {'Authorization': 'Bearer $accessToken'},
      3,
      'Token Introspection (Bearer + GCM)',
    );
  }

  /// Step 5: Refresh tokens (Bearer + GCM).
  Future<StepResult> refreshToken(
    SessionContext session,
    String plaintext,
    String accessToken,
  ) {
    return _postEncrypted(
      '/v1/token',
      session,
      plaintext,
      {'Authorization': 'Bearer $accessToken'},
      5,
      'Token Refresh (Bearer + GCM)',
    );
  }

  /// Step 6: Revoke token (Bearer + GCM).
  Future<StepResult> revokeToken(
    SessionContext session,
    String plaintext,
    String accessToken,
  ) {
    return _postEncrypted(
      '/v1/revoke',
      session,
      plaintext,
      {'Authorization': 'Bearer $accessToken'},
      6,
      'Token Revocation (Bearer + GCM)',
    );
  }

  /// Core: encrypt body -> POST -> decrypt response.
  Future<StepResult> _postEncrypted(
    String path,
    SessionContext session,
    String plaintext,
    Map<String, String> authHeaders,
    int stepNum,
    String stepName,
  ) async {
    final sw = Stopwatch()..start();
    try {
      final nonce = _crypto.generateNonce();
      final ts = DateTime.now().millisecondsSinceEpoch.toString();
      final aad = _crypto.buildAad(ts, nonce, session.kid, session.clientId);

      final encryptedPayload = await _crypto.encrypt(
        plaintext,
        session.sessionKey,
        aad,
      );

      final headers = <String, String>{
        'Content-Type': 'application/json',
        'X-Kid': session.kid,
        'X-Idempotency-Key': '$ts.$nonce',
        'X-ClientId': session.clientId,
        ...authHeaders,
      };

      final requestBody = jsonEncode(
        EncryptedPayload(payload: encryptedPayload).toJson(),
      );

      final response = await http.post(
        Uri.parse('${AppConfig.sidecarUrl}/api$path'),
        headers: headers,
        body: requestBody,
      );

      final respHeaders = _extractResponseHeaders(response);

      if (response.statusCode != 200) {
        sw.stop();
        return StepResult(
          step: stepNum,
          name: stepName,
          requestHeaders: headers,
          requestBodyPlaintext: plaintext,
          requestBodyEncrypted: encryptedPayload,
          responseHeaders: respHeaders,
          responseBodyDecrypted: response.body,
          durationMs: sw.elapsedMilliseconds,
          error: 'HTTP ${response.statusCode}: ${response.body}',
        );
      }

      final (respEncrypted, decrypted) = await _decryptResponse(
        response.body,
        respHeaders,
        session,
      );

      sw.stop();
      return StepResult(
        step: stepNum,
        name: stepName,
        requestHeaders: headers,
        requestBodyPlaintext: plaintext,
        requestBodyEncrypted: encryptedPayload,
        responseHeaders: respHeaders,
        responseBodyEncrypted: respEncrypted,
        responseBodyDecrypted: decrypted,
        durationMs: sw.elapsedMilliseconds,
        success: true,
      );
    } catch (e) {
      sw.stop();
      return StepResult(
        step: stepNum,
        name: stepName,
        requestBodyPlaintext: plaintext,
        durationMs: sw.elapsedMilliseconds,
        error: e.toString(),
      );
    }
  }

  Future<(String, String)> _decryptResponse(
    String responseBody,
    Map<String, String> respHeaders,
    SessionContext session,
  ) async {
    final respKid = respHeaders['x-kid'];
    final respIdempKey = respHeaders['x-idempotency-key'];

    if (respKid != null && respIdempKey != null) {
      final parts = respIdempKey.split('.');
      final respAad = _crypto.buildAad(
        parts[0],
        parts[1],
        respKid,
        session.clientId,
      );

      final resBody = EncryptedPayload.fromJson(
        jsonDecode(responseBody) as Map<String, dynamic>,
      );

      final decrypted = await _crypto.decrypt(
        resBody.payload,
        session.sessionKey,
        respAad,
      );

      return (resBody.payload, decrypted);
    }

    return ('', responseBody);
  }

  Map<String, String> _extractResponseHeaders(http.Response response) {
    final result = <String, String>{};
    for (final key in ['x-kid', 'x-idempotency-key', 'content-type']) {
      final value = response.headers[key];
      if (value != null) result[key] = value;
    }
    return result;
  }
}
