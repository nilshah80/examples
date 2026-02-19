import 'dart:convert';

import 'package:flutter/material.dart';

import '../config.dart';
import '../models/session_context.dart';
import '../models/step_result.dart';
import '../services/crypto_service.dart';
import '../services/identity_service.dart';
import '../services/session_service.dart';

class _StepDef {
  final int n;
  final String title;
  final String desc;
  final String btn;
  final bool isSession;

  const _StepDef(this.n, this.title, this.desc, this.btn,
      {this.isSession = false});
}

const _steps = [
  _StepDef(
    1,
    'Session Init (Anonymous ECDH)',
    'Generate ECDH P-256 keypair on-device, exchange public keys with sidecar, '
        'derive AES-256-GCM session key via HKDF-SHA256. Anonymous session TTL: 30 minutes.',
    'POST /api/v1/session/init',
    isSession: true,
  ),
  _StepDef(
    2,
    'Token Issue (HMAC-SHA256 + GCM)',
    'Encrypt request body with AES-256-GCM and authenticate via '
        'X-Signature: HMAC-SHA256(plaintext body). HMAC is computed over the plaintext body before encryption.',
    'POST /api/v1/token/issue',
  ),
  _StepDef(
    3,
    'Token Introspection (Bearer + GCM)',
    'Verify the issued token is active and retrieve its claims. '
        'Auth via Authorization: Bearer.',
    'POST /api/v1/introspect',
  ),
  _StepDef(
    4,
    'Session Refresh (Authenticated)',
    'Create a new ECDH session with Authorization: Bearer + X-Subject. '
        'Authenticated session TTL: 1 hour. Old session key is zeroized.',
    'POST /api/v1/session/init',
    isSession: true,
  ),
  _StepDef(
    5,
    'Token Refresh (Bearer + GCM)',
    'Rotate tokens using the refresh token. Uses the new authenticated session.',
    'POST /api/v1/token',
  ),
  _StepDef(
    6,
    'Token Revocation (Bearer + GCM)',
    'Revoke the refresh token — this revokes the entire token family. '
        'RFC 7009 compliant.',
    'POST /api/v1/revoke',
  ),
];

class JourneyScreen extends StatefulWidget {
  const JourneyScreen({super.key});

  @override
  State<JourneyScreen> createState() => _JourneyScreenState();
}

class _JourneyScreenState extends State<JourneyScreen> {
  final _crypto = CryptoService();
  late final _sessionSvc = SessionService(_crypto);
  late final _identitySvc = IdentityService(_crypto);

  int _currentStep = 1;
  bool _loading = false;
  final Map<int, dynamic> _results = {};

  // Journey state
  SessionContext? _session;
  String _accessToken = '';
  String _refreshToken = '';

  Future<void> _runStep(int n) async {
    setState(() => _loading = true);

    try {
      switch (n) {
        case 1:
          _session = await _sessionSvc.initSession();
          _accessToken = '';
          _refreshToken = '';
          setState(() {
            _results[1] = {
              'success': true,
              'sessionId': _session!.sessionId,
              'kid': _session!.kid,
              'authenticated': _session!.authenticated,
              'expiresInSec': _session!.expiresInSec,
            };
            _currentStep = 2;
          });
          break;

        case 2:
          final body = jsonEncode({
            'audience': 'orders-api',
            'scope': 'orders.read',
            'subject': AppConfig.subject,
            'include_refresh_token': true,
            'single_session': true,
            'custom_claims': {'partner_id': 'PARTNER-001', 'region': 'us-east-1'},
          });
          final result = await _identitySvc.issueToken(_session!, body);
          if (result.success) {
            final data = jsonDecode(result.responseBodyDecrypted);
            _accessToken = data['access_token'] as String;
            _refreshToken = (data['refresh_token'] as String?) ?? '';
          }
          setState(() {
            _results[2] = result;
            if (result.success) _currentStep = 3;
          });
          break;

        case 3:
          final body = jsonEncode({'token': _accessToken});
          final result = await _identitySvc.introspectToken(
            _session!,
            body,
            _accessToken,
          );
          setState(() {
            _results[3] = result;
            if (result.success) _currentStep = 4;
          });
          break;

        case 4:
          _session = await _sessionSvc.refreshSession(
            _accessToken,
            AppConfig.subject,
            _session,
          );
          setState(() {
            _results[4] = {
              'success': true,
              'sessionId': _session!.sessionId,
              'kid': _session!.kid,
              'authenticated': _session!.authenticated,
              'expiresInSec': _session!.expiresInSec,
            };
            _currentStep = 5;
          });
          break;

        case 5:
          final body = jsonEncode({
            'grant_type': 'refresh_token',
            'refresh_token': _refreshToken,
          });
          final result = await _identitySvc.refreshToken(
            _session!,
            body,
            _accessToken,
          );
          if (result.success) {
            final data = jsonDecode(result.responseBodyDecrypted);
            _accessToken = data['access_token'] as String;
            _refreshToken = (data['refresh_token'] as String?) ?? '';
          }
          setState(() {
            _results[5] = result;
            if (result.success) _currentStep = 6;
          });
          break;

        case 6:
          final body = jsonEncode({
            'token': _refreshToken,
            'token_type_hint': 'refresh_token',
          });
          final result = await _identitySvc.revokeToken(
            _session!,
            body,
            _accessToken,
          );
          setState(() {
            _results[6] = result;
            if (result.success) _currentStep = 7;
          });
          break;
      }
    } catch (e) {
      setState(() {
        _results[n] = {'success': false, 'error': e.toString()};
      });
    }

    setState(() => _loading = false);
  }

  void _reset() {
    _session?.zeroize();
    setState(() {
      _session = null;
      _accessToken = '';
      _refreshToken = '';
      _currentStep = 1;
      _results.clear();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            // Header
            Text(
              'Identity Service — External Client',
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                    color: Colors.amber.shade300,
                    fontWeight: FontWeight.bold,
                  ),
            ),
            const SizedBox(height: 4),
            Text(
              'OAuth2 Token Flow with AES-256-GCM Encryption (HMAC Auth)',
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Colors.white54,
                  ),
            ),
            Padding(
              padding: const EdgeInsets.only(top: 4),
              child: Text(
                'Auth: HMAC-SHA256  •  Crypto: Dart (on-device)  •  Client: ${AppConfig.clientId}',
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Colors.white38,
                      fontFamily: 'monospace',
                      fontSize: 11,
                    ),
              ),
            ),
            const SizedBox(height: 20),

            // Step cards
            for (final step in _steps) _buildStepCard(step),

            // Completion card
            if (_currentStep > 6) ...[
              const SizedBox(height: 16),
              Card(
                color: Colors.green.shade900.withValues(alpha: 0.3),
                child: Padding(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    children: [
                      const Icon(Icons.check_circle,
                          color: Colors.green, size: 48),
                      const SizedBox(height: 12),
                      const Text(
                        'Journey Complete',
                        style: TextStyle(
                          fontSize: 20,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 8),
                      const Text('All 6 steps executed successfully.'),
                      const SizedBox(height: 16),
                      OutlinedButton(
                        onPressed: _reset,
                        child: const Text('Reset and start over'),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildStepCard(_StepDef step) {
    final isActive = _currentStep == step.n;
    final isDone = _currentStep > step.n;
    final result = _results[step.n];

    final statusText = isDone
        ? 'Done'
        : isActive
            ? 'Ready'
            : 'Waiting';
    final statusColor = isDone
        ? Colors.green
        : isActive
            ? Colors.amber
            : Colors.white24;

    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      color: isActive
          ? Colors.amber.shade900.withValues(alpha: 0.2)
          : isDone
              ? Colors.green.shade900.withValues(alpha: 0.1)
              : const Color(0xFF1A1A2E),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(
          color: isActive
              ? Colors.amber.shade700
              : isDone
                  ? Colors.green.shade800
                  : Colors.white10,
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header row
            Row(
              children: [
                CircleAvatar(
                  radius: 14,
                  backgroundColor: statusColor,
                  child: Text(
                    '${step.n}',
                    style: const TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.bold,
                      color: Colors.white,
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    step.title,
                    style: const TextStyle(
                      fontSize: 15,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: statusColor.withValues(alpha: 0.2),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text(
                    statusText,
                    style: TextStyle(fontSize: 11, color: statusColor),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),

            // Description
            Text(
              step.desc,
              style: const TextStyle(fontSize: 12, color: Colors.white54),
            ),
            const SizedBox(height: 12),

            // Action button
            SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                onPressed: (_loading || !isActive) ? null : () => _runStep(step.n),
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.amber.shade800,
                  foregroundColor: Colors.white,
                  disabledBackgroundColor: Colors.white10,
                  disabledForegroundColor: Colors.white24,
                ),
                child: Text(
                  _loading && isActive ? 'Processing...' : step.btn,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 13,
                  ),
                ),
              ),
            ),

            // Result display
            if (result != null) ...[
              const SizedBox(height: 12),
              _buildResult(step, result),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildResult(_StepDef step, dynamic result) {
    if (step.isSession && result is Map) {
      return _buildSessionResult(result);
    }
    if (result is StepResult) {
      return _buildStepResult(result);
    }
    if (result is Map && result['error'] != null) {
      return _buildErrorResult(result);
    }
    return const SizedBox.shrink();
  }

  Widget _buildSessionResult(Map result) {
    final success = result['success'] as bool;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: success
            ? Colors.green.shade900.withValues(alpha: 0.3)
            : Colors.red.shade900.withValues(alpha: 0.3),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                success ? Icons.check_circle : Icons.error,
                color: success ? Colors.green : Colors.red,
                size: 18,
              ),
              const SizedBox(width: 6),
              Text(
                success ? 'Success' : 'Failed',
                style: TextStyle(
                  fontWeight: FontWeight.bold,
                  color: success ? Colors.green : Colors.red,
                ),
              ),
            ],
          ),
          if (result['error'] != null) ...[
            const SizedBox(height: 6),
            Text(
              result['error'] as String,
              style: const TextStyle(color: Colors.red, fontSize: 12),
            ),
          ],
          if (result['sessionId'] != null) ...[
            const SizedBox(height: 8),
            _kvRow('Session ID', result['sessionId'] as String),
            _kvRow('Key ID (kid)', result['kid'] as String),
            _kvRow('Authenticated', '${result['authenticated']}'),
            _kvRow('TTL', '${result['expiresInSec']}s'),
          ],
        ],
      ),
    );
  }

  Widget _buildStepResult(StepResult r) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: r.success
            ? Colors.green.shade900.withValues(alpha: 0.3)
            : Colors.red.shade900.withValues(alpha: 0.3),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                r.success ? Icons.check_circle : Icons.error,
                color: r.success ? Colors.green : Colors.red,
                size: 18,
              ),
              const SizedBox(width: 6),
              Text(
                r.success ? 'Success' : 'Failed',
                style: TextStyle(
                  fontWeight: FontWeight.bold,
                  color: r.success ? Colors.green : Colors.red,
                ),
              ),
              const Spacer(),
              Text(
                '${r.durationMs}ms',
                style: const TextStyle(
                  color: Colors.white54,
                  fontFamily: 'monospace',
                  fontSize: 12,
                ),
              ),
            ],
          ),
          if (r.error != null) ...[
            const SizedBox(height: 6),
            Text(
              r.error!,
              style: const TextStyle(color: Colors.red, fontSize: 12),
            ),
          ],
          if (r.requestBodyPlaintext.isNotEmpty)
            _expandableJson('Request Body (plaintext)', r.requestBodyPlaintext),
          if (r.requestBodyEncrypted.isNotEmpty)
            _expandableText('Request Body (encrypted)', r.requestBodyEncrypted),
          if (r.responseBodyEncrypted.isNotEmpty)
            _expandableText(
                'Response Body (encrypted)', r.responseBodyEncrypted),
          if (r.responseBodyDecrypted.isNotEmpty)
            _expandableJson(
                'Response Body (decrypted)', r.responseBodyDecrypted,
                initiallyExpanded: true),
          if (r.requestHeaders.isNotEmpty)
            _expandableText('Request Headers',
                const JsonEncoder.withIndent('  ').convert(r.requestHeaders)),
          if (r.responseHeaders.isNotEmpty)
            _expandableText('Response Headers',
                const JsonEncoder.withIndent('  ').convert(r.responseHeaders)),
        ],
      ),
    );
  }

  Widget _buildErrorResult(Map result) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.red.shade900.withValues(alpha: 0.3),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          const Icon(Icons.error, color: Colors.red, size: 18),
          const SizedBox(width: 6),
          Expanded(
            child: Text(
              result['error'] as String,
              style: const TextStyle(color: Colors.red, fontSize: 12),
            ),
          ),
        ],
      ),
    );
  }

  Widget _kvRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 120,
            child: Text(
              label,
              style: const TextStyle(color: Colors.white54, fontSize: 12),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 11,
                color: Colors.white70,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _expandableJson(String title, String json,
      {bool initiallyExpanded = false}) {
    String formatted;
    try {
      formatted = const JsonEncoder.withIndent('  ')
          .convert(jsonDecode(json));
    } catch (_) {
      formatted = json;
    }
    return _expandableText(title, formatted,
        initiallyExpanded: initiallyExpanded);
  }

  Widget _expandableText(String title, String text,
      {bool initiallyExpanded = false}) {
    return Theme(
      data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
      child: ExpansionTile(
        title: Text(
          title,
          style: const TextStyle(fontSize: 12, color: Colors.amber),
        ),
        tilePadding: EdgeInsets.zero,
        initiallyExpanded: initiallyExpanded,
        childrenPadding: const EdgeInsets.only(bottom: 8),
        children: [
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: Colors.black26,
              borderRadius: BorderRadius.circular(6),
            ),
            child: SelectableText(
              text,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 11,
                color: Colors.white60,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
