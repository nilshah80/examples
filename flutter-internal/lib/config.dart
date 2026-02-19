import 'package:flutter_dotenv/flutter_dotenv.dart';

class AppConfig {
  static String get clientId => dotenv.env['CLIENT_ID'] ?? 'dev-client';
  static String get clientSecret =>
      dotenv.env['CLIENT_SECRET'] ?? 'DevSec-LwgT7vXGZk2njwglKWZBYW7q1sdNTElTQ!';
  static String get subject => dotenv.env['SUBJECT'] ?? 'test-user';
  static String get sidecarUrl =>
      dotenv.env['SIDECAR_URL'] ?? 'http://localhost:8141';
}
