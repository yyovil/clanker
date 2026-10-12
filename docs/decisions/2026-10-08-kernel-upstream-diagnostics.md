# Kernel upstream diagnostics

Kernel startup errors previously became a generic local 503 before Hermes could
record the original exception. A request timeout, an upstream HTTP rejection and
a plugin failure therefore appeared identical in operator logs.

The protected Kernel client now records a structured `kernel_upstream_failure`
warning before translating a failure into a safe tool response. Creation,
ownership lookup, deletion and deletion verification use the same diagnostics.
Each failed operation has a random `diagnostic_ref`. An uncertain creation saves
that reference alongside its existing pending marker, so subsequent retry/reset
blocks point to the original failure without issuing another provider request.

The warning contains the operation, a hashed task reference when available,
route templates, request duration, configured timeout, actual upstream status
(null when no response arrived), an upstream request ID when supplied, failure
category and exception chain with source locations. HTTP error responses retain
only selected scalar `code`, `message` and `error` fields. Non-JSON bodies are
identified but omitted. The local tool status remains separate from upstream
HTTP status; an application 503 does not imply Kernel returned HTTP 503.

Diagnostic text is bounded and sanitized before constructing a LogRecord.
The backend key and its encoded forms, bearer credentials, control URLs and
registered private vault values are removed; generic secret redaction is forced
even if the profile disables ordinary redaction. Request bodies, raw headers,
successful response bodies, arbitrary error fields, traceback locals and raw
`exc_info` never enter the log queue. Selected provider messages are untrusted
diagnostic text, not instructions or user-facing content.

Hermes's existing rotating logs and profile routing retain these warnings in the
executing profile's `logs/agent.log` and `logs/errors.log`. Search for the error's
`Reference` value or `kernel_upstream_failure`. Transport-home logs are not a
substitute for the executing task profile's logs. No new telemetry destination,
retry, local fallback or remote cleanup action is introduced.

This follows the [OpenTelemetry HTTP conventions](https://opentelemetry.io/docs/specs/semconv/http/http-spans/)
for distinguishing received HTTP status from transport errors, and the
[OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
on correlation, excluded secrets and sanitizing untrusted log data.
