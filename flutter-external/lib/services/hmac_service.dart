import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:flutter/foundation.dart' show kIsWeb;

/// HMAC-SHA256 signature computation for external client authentication.
///
/// Signature format:
///   bodyHash     = SHA-256(plaintextBody).hex()
///   stringToSign = "METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_HASH"
///   signature    = HMAC-SHA256(secret, stringToSign).hex()
///
/// IMPORTANT: HMAC is computed over the PLAINTEXT body (before GCM encryption).
class HmacService {
  late final HashAlgorithm _sha256;
  late final MacAlgorithm _hmac;

  HmacService() {
    if (kIsWeb) {
      _sha256 = Sha256();
      _hmac = Hmac.sha256();
    } else {
      _sha256 = DartSha256();
      _hmac = DartHmac.sha256();
    }
  }

  Future<String> computeSignature(
    String method,
    String path,
    String timestamp,
    String nonce,
    String body,
    String secret,
  ) async {
    // SHA-256 hash of the plaintext body -> lowercase hex
    final bodyBytes = utf8.encode(body);
    final bodyHash = await _sha256.hash(bodyBytes);
    final bodyHashHex = _bytesToHexLower(Uint8List.fromList(bodyHash.bytes));

    // Build string-to-sign
    final stringToSign =
        '${method.toUpperCase()}\n$path\n$timestamp\n$nonce\n$bodyHashHex';

    // HMAC-SHA256(secret, stringToSign) -> lowercase hex
    final secretKey = SecretKey(utf8.encode(secret));
    final mac = await _hmac.calculateMac(
      utf8.encode(stringToSign),
      secretKey: secretKey,
    );

    return _bytesToHexLower(Uint8List.fromList(mac.bytes));
  }

  String _bytesToHexLower(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
