package pro.lawcybug.scanner.detectors.info;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.IssueFactory;
import pro.lawcybug.scanner.core.PassiveDetector;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive information-disclosure detector. Looks for secrets, stack
 * traces, path disclosures and sensitive keys in HTTP responses.
 *
 * Each signature is a {Pattern, issue name, severity, recommendation}.
 */
public final class InfoDisclosureDetector implements PassiveDetector {

    public static final String ID = "info.disclosure";

    private record Signature(Pattern pattern, String issueName,
                              AuditIssueSeverity severity, String remediation) {}

    private static final List<Signature> SIGNATURES = List.of(
            // ── Stack traces ────────────────────────────────────────────────
            new Signature(Pattern.compile("at [a-zA-Z_$][a-zA-Z0-9_$]*(\\.[a-zA-Z_$][a-zA-Z0-9_$]*)+\\(.*\\.java:[0-9]+\\)", Pattern.MULTILINE),
                    "Java Stack Trace Disclosure", AuditIssueSeverity.LOW,
                    "Configure production error handlers to return generic error messages. Log full stack traces server-side only."),
            new Signature(Pattern.compile("Traceback \\(most recent call last\\)", Pattern.CASE_INSENSITIVE),
                    "Python Traceback Disclosure", AuditIssueSeverity.LOW,
                    "Set DEBUG=False in Django/Flask. Use custom error handlers that never expose tracebacks."),
            new Signature(Pattern.compile("System\\.Exception|System\\.NullReferenceException|at System\\.", Pattern.CASE_INSENSITIVE),
                    ".NET Exception Disclosure", AuditIssueSeverity.LOW,
                    "Configure <customErrors mode='On'> and suppress verbose exception details in production."),
            new Signature(Pattern.compile("Fatal error.*PHP|Warning.*PHP|Parse error.*PHP", Pattern.CASE_INSENSITIVE),
                    "PHP Error Disclosure", AuditIssueSeverity.LOW,
                    "Set display_errors=Off and log_errors=On in php.ini for production."),
            new Signature(Pattern.compile("ORA-[0-9]{4,5}:|PLS-[0-9]{5}:", Pattern.CASE_INSENSITIVE),
                    "Oracle Database Error Disclosure", AuditIssueSeverity.MEDIUM,
                    "Suppress or genericize Oracle error messages in the application layer."),

            // ── Credentials / Secrets ───────────────────────────────────────
            new Signature(Pattern.compile("(?i)(api[_\\-]?key|api[_\\-]?secret|access[_\\-]?token|auth[_\\-]?token|client[_\\-]?secret)[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9+/=_\\-]{20,})", Pattern.CASE_INSENSITIVE),
                    "API Key / Secret Disclosure in Response", AuditIssueSeverity.HIGH,
                    "Remove secrets from HTTP responses. Rotate any exposed credentials immediately."),
            new Signature(Pattern.compile("-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"),
                    "Private Key Disclosure in Response", AuditIssueSeverity.HIGH,
                    "Remove private key material from HTTP responses. Rotate the key pair immediately."),
            new Signature(Pattern.compile("(?i)password[\"']?\\s*[:=]\\s*[\"']?[^\\s\"']{8,}"),
                    "Password Disclosure in Response", AuditIssueSeverity.HIGH,
                    "Remove passwords from HTTP responses. Review logging and API design."),
            new Signature(Pattern.compile("AKIA[0-9A-Z]{16}"),
                    "AWS Access Key ID Disclosure", AuditIssueSeverity.HIGH,
                    "Remove AWS credentials from responses. Rotate the key immediately via AWS IAM."),
            new Signature(Pattern.compile("(?i)(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{59,})"),
                    "GitHub Personal Access Token Disclosure", AuditIssueSeverity.HIGH,
                    "Remove GitHub tokens from responses. Revoke the token immediately in GitHub settings."),
            new Signature(Pattern.compile("(?i)(sk-[A-Za-z0-9]{48}|sk-proj-[A-Za-z0-9\\-]{80,})"),
                    "OpenAI API Key Disclosure", AuditIssueSeverity.HIGH,
                    "Remove OpenAI keys from responses. Revoke at platform.openai.com immediately."),
            new Signature(Pattern.compile("(?i)(AIza[A-Za-z0-9\\-_]{35})"),
                    "Google API Key Disclosure", AuditIssueSeverity.HIGH,
                    "Remove Google API keys from responses. Revoke and rotate at console.cloud.google.com."),
            new Signature(Pattern.compile("(?i)xox[baprs]-[A-Za-z0-9\\-]{10,}"),
                    "Slack Token Disclosure", AuditIssueSeverity.HIGH,
                    "Remove Slack tokens from responses. Revoke at api.slack.com."),

            // ── Path / environment disclosure ────────────────────────────────
            new Signature(Pattern.compile("(/var/www|/home/[a-z]+|/etc/[a-z]+|C:\\\\(Users|inetpub|Windows|Program Files))"),
                    "Internal File System Path Disclosure", AuditIssueSeverity.LOW,
                    "Suppress file system paths in error messages and responses."),
            new Signature(Pattern.compile("(?i)(DB_PASSWORD|DATABASE_URL|DATABASE_PASSWORD)\\s*=\\s*[^\\s&\"']{4,}"),
                    "Database Credentials in Response (env-style)", AuditIssueSeverity.HIGH,
                    "Never expose environment variable values in HTTP responses."),

            // ── Debug / dev artifacts ────────────────────────────────────────
            new Signature(Pattern.compile("(?i)(x-debug-token|x-symfony-profiler|debugbar|x-laravel-debugbar)", Pattern.CASE_INSENSITIVE),
                    "Debug Toolbar / Profiler Active in Production", AuditIssueSeverity.MEDIUM,
                    "Disable debug toolbars, profilers and dev-only middleware in production environments."),
            new Signature(Pattern.compile("phpinfo\\(\\)|PHP Version|PHP Credits|php extension"),
                    "PHP Info Page Exposed", AuditIssueSeverity.MEDIUM,
                    "Remove phpinfo() pages from production environments."),
            new Signature(Pattern.compile("laravel_session|XSRF-TOKEN.*laravel"),
                    "Laravel Framework Fingerprint", AuditIssueSeverity.LOW,
                    "Informational. Consider removing or obfuscating framework-specific cookie names."),

            // ── Version banners ──────────────────────────────────────────────
            new Signature(Pattern.compile("(?i)(Apache/[0-9]|nginx/[0-9]|IIS/[0-9]|Tomcat/[0-9]|Jetty/[0-9]|Express [0-9])"),
                    "Web Server Version Disclosure in Response Body", AuditIssueSeverity.LOW,
                    "Remove version banners from error pages and response bodies.")
    );

    @Override public String id()          { return ID; }
    @Override public String displayName() { return "Information Disclosure"; }
    @Override public String description() { return "Passive checks for secrets, stack traces, API keys, internal paths and debug artifacts in responses."; }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx, HttpRequestResponse base) {
        List<AuditIssue> issues = new ArrayList<>();
        if (base.response() == null) return issues;
        String body = base.response().bodyToString();
        String url  = base.request().url();

        // Apply each signature
        for (Signature sig : SIGNATURES) {
            Matcher m = sig.pattern().matcher(body);
            if (m.find()) {
                String matched = m.group();
                int start = m.start();
                int end   = m.end();
                HttpRequestResponse highlighted = IssueFactory.withResponseBodyHighlight(base, start, end);

                issues.add(IssueFactory.build(
                        sig.issueName(),
                        IssueFactory.evidenceParagraph("Evidence (truncated)", matched.substring(0, Math.min(200, matched.length()))),
                        sig.remediation(),
                        url, sig.severity(), AuditIssueConfidence.FIRM,
                        "The response body matches a pattern associated with '" + sig.issueName()
                                + "'. The matched content was found in the passive response and was "
                                + "not injected by the scanner.",
                        highlighted));
            }
        }
        return issues;
    }
}
