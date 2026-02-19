/// Captures the full request/response lifecycle of a single step.
class StepResult {
  final int step;
  final String name;
  final Map<String, String> requestHeaders;
  final String requestBodyPlaintext;
  final String requestBodyEncrypted;
  final Map<String, String> responseHeaders;
  final String responseBodyEncrypted;
  final String responseBodyDecrypted;
  final int durationMs;
  final bool success;
  final String? error;

  StepResult({
    required this.step,
    required this.name,
    this.requestHeaders = const {},
    this.requestBodyPlaintext = '',
    this.requestBodyEncrypted = '',
    this.responseHeaders = const {},
    this.responseBodyEncrypted = '',
    this.responseBodyDecrypted = '',
    this.durationMs = 0,
    this.success = false,
    this.error,
  });
}
