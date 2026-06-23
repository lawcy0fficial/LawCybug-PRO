package pro.lawcybug.scanner.core;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Single ScanCheck registered with Burp that fans every passive/active
 * audit call out to all enabled detectors, collects their issues, logs
 * and reports them to the FindingsStore for the live UI, and isolates
 * each detector so one buggy/throwing detector can never take down the
 * whole audit pass for every other detector.
 *
 * We deliberately use the combined ScanCheck interface (registered via
 * Scanner.registerScanCheck) rather than the newer split
 * ActiveScanCheck/PassiveScanCheck registration methods, because at the
 * time of writing it is still fully supported across current Burp
 * releases and is the most broadly documented/stable surface to build
 * against. If a future Burp release removes it, migrating to
 * registerActiveScanCheck/registerPassiveScanCheck is a small, isolated
 * change confined to this one class.
 */
public final class DetectorEngine implements ScanCheck {

    private final DetectorContext context;
    private final Logging logging;
    private final List<PassiveDetector> passiveDetectors = new CopyOnWriteArrayList<>();
    private final List<ActiveDetector> activeDetectors = new CopyOnWriteArrayList<>();

    public DetectorEngine(DetectorContext context) {
        this.context = context;
        this.logging = context.api().logging();
    }

    public void registerPassive(PassiveDetector detector) {
        passiveDetectors.add(detector);
    }

    public void registerActive(ActiveDetector detector) {
        activeDetectors.add(detector);
    }

    public List<PassiveDetector> passiveDetectors() {
        return passiveDetectors;
    }

    public List<ActiveDetector> activeDetectors() {
        return activeDetectors;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        if (context.settings().isOnlyScanInScope()
                && !context.api().scope().isInScope(baseRequestResponse.request().url())) {
            return AuditResult.auditResult(List.of());
        }

        List<AuditIssue> issues = new ArrayList<>();
        for (PassiveDetector detector : passiveDetectors) {
            if (!context.settings().isDetectorEnabled(detector.id())) {
                continue;
            }
            try {
                List<AuditIssue> found = detector.analyze(context, baseRequestResponse);
                if (found != null && !found.isEmpty()) {
                    issues.addAll(found);
                    for (AuditIssue issue : found) {
                        context.findingsStore().add(new Finding(detector.id(), issue));
                    }
                }
            } catch (Exception e) {
                logging.logToError("[LawCyBug.pro] passive detector '" + detector.id()
                        + "' threw: " + e);
            }
        }
        return AuditResult.auditResult(issues);
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        if (context.settings().isOnlyScanInScope()
                && !context.api().scope().isInScope(baseRequestResponse.request().url())) {
            return AuditResult.auditResult(List.of());
        }

        List<AuditIssue> issues = new ArrayList<>();
        for (ActiveDetector detector : activeDetectors) {
            if (!context.settings().isDetectorEnabled(detector.id())) {
                continue;
            }
            try {
                List<AuditIssue> found = detector.analyze(context, baseRequestResponse, insertionPoint);
                if (found != null && !found.isEmpty()) {
                    issues.addAll(found);
                    for (AuditIssue issue : found) {
                        context.findingsStore().add(new Finding(detector.id(), issue));
                    }
                }
            } catch (Exception e) {
                logging.logToError("[LawCyBug.pro] active detector '" + detector.id()
                        + "' on insertion point '" + insertionPoint.name() + "' threw: " + e);
            }
        }
        return AuditResult.auditResult(issues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        boolean sameName = existingIssue.name().equals(newIssue.name());
        boolean sameUrlPath = existingIssue.baseUrl().equals(newIssue.baseUrl());
        if (sameName && sameUrlPath) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }
}
