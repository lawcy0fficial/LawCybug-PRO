package pro.lawcybug.scanner.detectors.cmdi;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.ActiveDetector;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.IssueFactory;
import pro.lawcybug.scanner.core.ScanSettings;
import pro.lawcybug.scanner.util.TimingUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Blind OS command injection via timing side-channel. Covers POSIX shells
 * (sh/bash), Windows cmd.exe, and PowerShell delay primitives, each with
 * several separator/chaining styles to handle different injection
 * contexts (mid-argument, end-of-line, subshell, etc.). Confirmed using
 * the same repeated-measurement statistics as the SQLi time-based
 * detector.
 */
public final class BlindCommandInjectionDetector implements ActiveDetector {

    public static final String ID = "cmdi.time_blind";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "OS Command Injection - Time-Based Blind";
    }

    @Override
    public String description() {
        return "Statistically-confirmed delay payloads across POSIX shells, cmd.exe and PowerShell.";
    }

    @Override
    public String category() {
        return "Injection";
    }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx, HttpRequestResponse base, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        ScanSettings settings = ctx.settings();
        int repeats = settings.getTimeBasedRequestRepeats();
        long delaySeconds = settings.getTimeBasedDelaySeconds();

        List<String[]> payloads = buildPayloads(delaySeconds); // {payload, os/shell label}
        if (settings.getIntensity() == ScanSettings.Intensity.QUICK) {
            payloads = payloads.subList(0, Math.min(4, payloads.size()));
        }

        TimingUtils.TimingResult baseline = TimingUtils.measure(ctx.api().http(), base.request(), repeats);

        for (String[] entry : payloads) {
            String payload = entry[0];
            String label = entry[1];

            HttpRequest delayedRequest = insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
            TimingUtils.TimingResult delayed = TimingUtils.measure(ctx.api().http(), delayedRequest, repeats);

            if (TimingUtils.isConvincingDelay(baseline, delayed, delaySeconds)) {
                HttpRequestResponse evidence = ctx.api().http().sendRequest(delayedRequest);

                String detail =
                        IssueFactory.evidenceParagraph("Insertion point", insertionPoint.name())
                                + IssueFactory.evidenceParagraph("Payload", payload)
                                + IssueFactory.evidenceParagraph("Shell/OS", label)
                                + IssueFactory.evidenceParagraph("Requested delay", delaySeconds + "s")
                                + IssueFactory.evidenceParagraph("Baseline timings (ms)", baseline.millis.toString())
                                + IssueFactory.evidenceParagraph("Delayed timings (ms)", delayed.millis.toString());

                issues.add(IssueFactory.build(
                        "OS Command Injection (Time-Based Blind) - " + label,
                        detail,
                        "Never pass user-controllable input to a shell or process-execution API. "
                                + "Use language-level APIs that take argument arrays (avoiding a shell "
                                + "entirely), and apply strict allow-list input validation if shelling out "
                                + "is unavoidable.",
                        base.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        "A " + label + " delay payload (" + delaySeconds + "s) was submitted " + repeats
                                + " times in the '" + insertionPoint.name() + "' parameter. Every "
                                + "measurement clearly exceeded both this endpoint's baseline latency and "
                                + "the expected delay threshold, indicating the payload was executed by a "
                                + "system shell.",
                        evidence
                ));
                break; // one confirmed shell is enough for this insertion point
            }
        }
        return issues;
    }

    private List<String[]> buildPayloads(long d) {
        List<String[]> list = new ArrayList<>();
        // POSIX (Linux/macOS) — several chaining/separator styles
        list.add(new String[]{";sleep " + d + ";", "POSIX shell (;)"});
        list.add(new String[]{"|sleep " + d, "POSIX shell (|)"});
        list.add(new String[]{"||sleep " + d, "POSIX shell (||)"});
        list.add(new String[]{"&&sleep " + d, "POSIX shell (&&)"});
        list.add(new String[]{"`sleep " + d + "`", "POSIX shell (backticks)"});
        list.add(new String[]{"$(sleep " + d + ")", "POSIX shell (subshell)"});
        list.add(new String[]{"\n sleep " + d + " \n", "POSIX shell (newline)"});
        // Windows cmd.exe
        list.add(new String[]{"&timeout /t " + d + "&", "Windows cmd.exe (&)"});
        list.add(new String[]{"|timeout /t " + d, "Windows cmd.exe (|)"});
        list.add(new String[]{"&ping -n " + (d + 1) + " 127.0.0.1&", "Windows cmd.exe (ping)"});
        // PowerShell
        list.add(new String[]{"; Start-Sleep -s " + d + " ;", "PowerShell"});
        list.add(new String[]{"| Start-Sleep -Seconds " + d, "PowerShell (pipe)"});
        return list;
    }
}
