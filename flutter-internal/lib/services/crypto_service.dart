import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:pointycastle/export.dart' as pc;
import 'package:uuid/uuid.dart';

/// Holds an ECDH P-256 keypair (pointycastle types on native, cryptography on web).
class EcdhKeyPair {
  final dynamic _privateKey; // pc.ECPrivateKey or EcKeyPair
  final dynamic _publicKey; // pc.ECPublicKey or null (extracted from EcKeyPair)

  EcdhKeyPair._(this._privateKey, this._publicKey);
}

/// Cryptographic operations: ECDH P-256, HKDF-SHA256, AES-256-GCM.
/// Web: Web Crypto API. Native: pointycastle (ECDH) + pure Dart (HKDF, AES-GCM).
class CryptoService {
  final _hkdf = DartHkdf(hmac: DartHmac.sha256(), outputLength: 32);
  final _aesGcm = DartAesGcm(secretKeyLength: 32, nonceLength: 12);
  final _uuid = const Uuid();

  // Web-only: platform ECDH via Web Crypto API
  late final Ecdh? _webEcdh = kIsWeb ? Ecdh.p256(length: 32) : null;

  // ── Base64 ──────────────────────────────────────

  String toBase64(Uint8List data) => base64.encode(data);
  Uint8List fromBase64(String b64) => Uint8List.fromList(base64.decode(b64));

  // ── Nonce ───────────────────────────────────────

  String generateNonce() => _uuid.v4();

  // ── ECDH P-256 ─────────────────────────────────

  /// Generate an ECDH P-256 keypair.
  Future<EcdhKeyPair> generateEcdhKeyPair() async {
    if (kIsWeb) {
      final kp = await _webEcdh!.newKeyPair();
      return EcdhKeyPair._(kp, null);
    }

    final params = pc.ECKeyGeneratorParameters(pc.ECCurve_secp256r1());
    final keyGen = pc.ECKeyGenerator()
      ..init(pc.ParametersWithRandom(params, _secureRandom()));
    final pair = keyGen.generateKeyPair();
    return EcdhKeyPair._(
      pair.privateKey as pc.ECPrivateKey,
      pair.publicKey as pc.ECPublicKey,
    );
  }

  /// Export EC public key as 65-byte uncompressed: 0x04 || X(32) || Y(32).
  Future<Uint8List> exportPublicKey(EcdhKeyPair keyPair) async {
    if (kIsWeb) {
      final ecKp = keyPair._privateKey as EcKeyPair;
      final publicKey = await ecKp.extractPublicKey();
      final x = _padTo32(Uint8List.fromList(publicKey.x));
      final y = _padTo32(Uint8List.fromList(publicKey.y));
      final result = Uint8List(65);
      result[0] = 0x04;
      result.setRange(1, 33, x);
      result.setRange(33, 65, y);
      return result;
    }

    final pub = keyPair._publicKey as pc.ECPublicKey;
    final q = pub.Q!;
    final x = _padTo32(_bigIntToBytes(q.x!.toBigInteger()!));
    final y = _padTo32(_bigIntToBytes(q.y!.toBigInteger()!));
    final result = Uint8List(65);
    result[0] = 0x04;
    result.setRange(1, 33, x);
    result.setRange(33, 65, y);
    return result;
  }

  /// Compute ECDH shared secret from our keypair and peer's 65-byte
  /// uncompressed public key (base64-encoded).
  Future<Uint8List> computeSharedSecret(
    EcdhKeyPair keyPair,
    String peerPublicKeyBase64,
  ) async {
    final peerBytes = fromBase64(peerPublicKeyBase64);
    if (peerBytes.length != 65 || peerBytes[0] != 0x04) {
      throw ArgumentError(
        'Invalid uncompressed EC public key (expected 65 bytes starting with 0x04)',
      );
    }

    if (kIsWeb) {
      final ecKp = keyPair._privateKey as EcKeyPair;
      final peerX = peerBytes.sublist(1, 33);
      final peerY = peerBytes.sublist(33, 65);
      final peerPubKey = EcPublicKey(
        x: peerX,
        y: peerY,
        type: KeyPairType.p256,
      );
      final shared = await _webEcdh!.sharedSecretKey(
        keyPair: ecKp,
        remotePublicKey: peerPubKey,
      );
      final bytes = await shared.extractBytes();
      return Uint8List.fromList(bytes);
    }

    // Native: pointycastle ECDH
    final curve = pc.ECCurve_secp256r1();
    final peerPoint = curve.curve.decodePoint(peerBytes);
    final priv = keyPair._privateKey as pc.ECPrivateKey;

    final agreement = pc.ECDHBasicAgreement()..init(priv);
    final sharedBigInt = agreement.calculateAgreement(
      pc.ECPublicKey(peerPoint, curve),
    );

    return _padTo32(_bigIntToBytes(sharedBigInt));
  }

  // ── HKDF-SHA256 ────────────────────────────────

  /// HKDF-SHA256 key derivation.
  /// salt = UTF-8(sessionId), info = UTF-8("SESSION|A256GCM|{clientId}")
  Future<Uint8List> deriveSessionKey(
    Uint8List sharedSecret,
    String sessionId,
    String clientId,
  ) async {
    final salt = utf8.encode(sessionId);
    final info = utf8.encode('SESSION|A256GCM|$clientId');

    final secretKey = SecretKey(sharedSecret);
    final derived = await _hkdf.deriveKey(
      secretKey: secretKey,
      nonce: salt,
      info: info,
    );

    final keyBytes = await derived.extractBytes();

    // Zeroize shared secret
    for (var i = 0; i < sharedSecret.length; i++) {
      sharedSecret[i] = 0;
    }

    return Uint8List.fromList(keyBytes);
  }

  // ── AES-256-GCM ────────────────────────────────

  /// AES-256-GCM encrypt.
  /// Returns base64( IV(12) || ciphertext || tag(16) ).
  Future<String> encrypt(
    String plaintext,
    Uint8List sessionKey,
    Uint8List aad,
  ) async {
    final plaintextBytes = utf8.encode(plaintext);
    final secretKey = SecretKey(sessionKey);

    final secretBox = await _aesGcm.encrypt(
      plaintextBytes,
      secretKey: secretKey,
      aad: aad,
    );

    // Assemble: IV(12) || ciphertext || tag(16)
    final nonce = secretBox.nonce; // 12 bytes
    final cipherText = secretBox.cipherText;
    final mac = secretBox.mac.bytes; // 16 bytes

    final result = Uint8List(12 + cipherText.length + 16);
    result.setRange(0, 12, nonce);
    result.setRange(12, 12 + cipherText.length, cipherText);
    result.setRange(12 + cipherText.length, result.length, mac);

    return toBase64(result);
  }

  /// AES-256-GCM decrypt.
  /// Input: base64( IV(12) || ciphertext || tag(16) ).
  Future<String> decrypt(
    String ciphertextBase64,
    Uint8List sessionKey,
    Uint8List aad,
  ) async {
    final encrypted = fromBase64(ciphertextBase64);

    final iv = encrypted.sublist(0, 12);
    final cipherText = encrypted.sublist(12, encrypted.length - 16);
    final tag = encrypted.sublist(encrypted.length - 16);

    final secretBox = SecretBox(
      cipherText,
      nonce: iv,
      mac: Mac(tag),
    );

    final secretKey = SecretKey(sessionKey);
    final plaintext = await _aesGcm.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: aad,
    );

    return utf8.decode(plaintext);
  }

  // ── AAD ─────────────────────────────────────────

  /// Build AAD: "timestamp|nonce|kid|clientId" as UTF-8 bytes.
  Uint8List buildAad(
    String timestamp,
    String nonce,
    String kid,
    String clientId,
  ) {
    return Uint8List.fromList(
      utf8.encode('$timestamp|$nonce|$kid|$clientId'),
    );
  }

  // ── Helpers ─────────────────────────────────────

  /// Left-pad byte array to exactly 32 bytes (EC coordinate padding).
  Uint8List _padTo32(Uint8List data) {
    if (data.length == 32) return data;
    if (data.length > 32) return data.sublist(data.length - 32);
    final padded = Uint8List(32);
    padded.setRange(32 - data.length, 32, data);
    return padded;
  }

  /// Convert BigInt to unsigned big-endian bytes.
  Uint8List _bigIntToBytes(BigInt n) {
    final hex = n.toRadixString(16);
    final padded = hex.length.isOdd ? '0$hex' : hex;
    final bytes = Uint8List(padded.length ~/ 2);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = int.parse(padded.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return bytes;
  }

  /// Secure random for pointycastle.
  pc.SecureRandom _secureRandom() {
    final rng = pc.FortunaRandom();
    final seed = Uint8List(32);
    final random = Random.secure();
    for (var i = 0; i < 32; i++) {
      seed[i] = random.nextInt(256);
    }
    rng.seed(pc.KeyParameter(seed));
    return rng;
  }
}
