import 'package:flutter_dotenv/flutter_dotenv.dart';

class AppConfig {
  static String get clientId =>
      dotenv.env['CLIENT_ID'] ?? 'external-partner-test';
  static String get clientSecret =>
      dotenv.env['CLIENT_SECRET'] ?? 'external-partner-hmac-secret-key-32chars!';
  static String get subject => dotenv.env['SUBJECT'] ?? 'hmac-user';
  static String get sidecarUrl =>
      dotenv.env['SIDECAR_URL'] ?? 'http://localhost:8141';
}
