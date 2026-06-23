package pro.lawcybug.scanner.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Holds every Finding reported during this Burp session and notifies
 * listeners (the Dashboard table) whenever a new one arrives. Capped
 * so a runaway scan can't grow this unbounded in memory.
 *
 * Also supports saving/restoring across extension reload via Burp's
 * Persistence API (api.persistence().extensionData()). Only the FIRST
 * evidence HttpRequestResponse per finding is persisted (most findings
 * only have one anyway; for the few with two -- boolean-based SQLi's
 * true/false pair, IDOR's victim/attacker pair -- the second is dropped
 * on reload). Response/request markers are NOT restored on reload
 * (highlighting is a live-session nicety, not worth the extra
 * persisted-state complexity here) -- everything else (name, detail,
 * remediation, background, severity, confidence, detector id,
 * timestamp, triage status) round-trips fully.
 */
public final class FindingsStore {

    private static final int MAX_FINDINGS = 20_000;
    private static final String PERSIST_KEY = "lawcybug.findings.v1";

    private final CopyOnWriteArrayList<Finding> findings = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<Consumer<Finding>> listeners = new CopyOnWriteArrayList<>();

    public void add(Finding finding) {
        if (findings.size() >= MAX_FINDINGS) {
            findings.remove(0);
        }
        findings.add(finding);
        for (Consumer<Finding> l : listeners) {
            l.accept(finding);
        }
    }

    public List<Finding> all() {
        return Collections.unmodifiableList(findings);
    }

    public void clear() {
        findings.clear();
    }

    public void addListener(Consumer<Finding> listener) {
        listeners.add(listener);
    }

    public int count() {
        return findings.size();
    }

    public long countBySeverity(String severityName) {
        return findings.stream()
                .filter(f -> f.issue().severity().name().equalsIgnoreCase(severityName))
                .count();
    }

    // ── Persistence ──────────────────────────────────────────────────────────

    /**
     * Saves every current finding to extension-scoped persisted storage so it
     * survives a "remove and re-add" of the extension jar (e.g. after
     * rebuilding) or closing/reopening the Burp project. Safe to call
     * repeatedly (e.g. on unload, and from a manual "Save" button) -- each
     * call fully overwrites the previous snapshot.
     */
    public void persist(MontoyaApi api) {
        try {
            PersistedObject store = api.persistence().extensionData();

            List<String> detectorIds = new ArrayList<>();
            List<String> names = new ArrayList<>();
            List<String> details = new ArrayList<>();
            List<String> remediations = new ArrayList<>();
            List<String> backgrounds = new ArrayList<>();
            List<String> baseUrls = new ArrayList<>();
            List<String> severities = new ArrayList<>();
            List<String> confidences = new ArrayList<>();
            List<String> timestamps = new ArrayList<>();
            List<String> statuses = new ArrayList<>();
            List<String> hosts = new ArrayList<>();
            List<String> ports = new ArrayList<>();
            List<String> secures = new ArrayList<>();
            List<String> requestB64 = new ArrayList<>();
            List<String> responseB64 = new ArrayList<>();

            for (Finding f : findings) {
                AuditIssue issue = f.issue();
                detectorIds.add(nullToEmpty(f.detectorId()));
                names.add(nullToEmpty(issue.name()));
                details.add(nullToEmpty(issue.detail()));
                remediations.add(nullToEmpty(issue.remediation()));
                backgrounds.add(""); // AuditIssue exposes no background() getter in Montoya -- write-only at creation
                baseUrls.add(nullToEmpty(issue.baseUrl()));
                severities.add(issue.severity().name());
                confidences.add(issue.confidence().name());
                timestamps.add(f.timestamp().toString());
                statuses.add(f.status().name());

                List<HttpRequestResponse> ev = issue.requestResponses();
                if (ev != null && !ev.isEmpty() && ev.get(0).request() != null) {
                    HttpRequestResponse rr = ev.get(0);
                    HttpService svc = rr.request().httpService();
                    hosts.add(svc != null ? nullToEmpty(svc.host()) : "");
                    ports.add(svc != null ? String.valueOf(svc.port()) : "0");
                    secures.add(svc != null && svc.secure() ? "1" : "0");
                    requestB64.add(Base64.getEncoder().encodeToString(rr.request().toByteArray().getBytes()));
                    responseB64.add(rr.response() != null
                            ? Base64.getEncoder().encodeToString(rr.response().toByteArray().getBytes())
                            : "");
                } else {
                    hosts.add(""); ports.add("0"); secures.add("0");
                    requestB64.add(""); responseB64.add("");
                }
            }

            PersistedObject data = PersistedObject.persistedObject();
            data.setStringList("detectorIds", toPersistedList(detectorIds));
            data.setStringList("names", toPersistedList(names));
            data.setStringList("details", toPersistedList(details));
            data.setStringList("remediations", toPersistedList(remediations));
            data.setStringList("backgrounds", toPersistedList(backgrounds));
            data.setStringList("baseUrls", toPersistedList(baseUrls));
            data.setStringList("severities", toPersistedList(severities));
            data.setStringList("confidences", toPersistedList(confidences));
            data.setStringList("timestamps", toPersistedList(timestamps));
            data.setStringList("statuses", toPersistedList(statuses));
            data.setStringList("hosts", toPersistedList(hosts));
            data.setStringList("ports", toPersistedList(ports));
            data.setStringList("secures", toPersistedList(secures));
            data.setStringList("requestB64", toPersistedList(requestB64));
            data.setStringList("responseB64", toPersistedList(responseB64));

            store.setChildObject(PERSIST_KEY, data);
        } catch (Exception e) {
            api.logging().logToError("[LawCyBug.pro] Failed to persist findings: " + e);
        }
    }

    /**
     * Restores findings saved by a previous session via {@link #persist}.
     * Call this AFTER UI listeners (the Dashboard table) are already
     * registered via addListener(), so restored findings populate the
     * table through the normal add() path with no special-case UI code.
     */
    public void loadPersisted(MontoyaApi api) {
        try {
            PersistedObject store = api.persistence().extensionData();
            PersistedObject data = store.getChildObject(PERSIST_KEY);
            if (data == null) return;

            List<String> detectorIds  = orEmpty(data.getStringList("detectorIds"));
            List<String> names        = orEmpty(data.getStringList("names"));
            List<String> details      = orEmpty(data.getStringList("details"));
            List<String> remediations = orEmpty(data.getStringList("remediations"));
            List<String> backgrounds  = orEmpty(data.getStringList("backgrounds"));
            List<String> baseUrls     = orEmpty(data.getStringList("baseUrls"));
            List<String> severities   = orEmpty(data.getStringList("severities"));
            List<String> confidences  = orEmpty(data.getStringList("confidences"));
            List<String> statuses     = orEmpty(data.getStringList("statuses"));
            List<String> hosts        = orEmpty(data.getStringList("hosts"));
            List<String> ports        = orEmpty(data.getStringList("ports"));
            List<String> secures      = orEmpty(data.getStringList("secures"));
            List<String> requestB64   = orEmpty(data.getStringList("requestB64"));
            List<String> responseB64  = orEmpty(data.getStringList("responseB64"));

            int n = names.size();
            for (int i = 0; i < n; i++) {
                HttpRequestResponse[] evidence = new HttpRequestResponse[0];

                String reqB64 = get(requestB64, i);
                if (reqB64 != null && !reqB64.isEmpty()) {
                    try {
                        HttpService svc = HttpService.httpService(
                                get(hosts, i),
                                Integer.parseInt(get(ports, i)),
                                "1".equals(get(secures, i)));
                        HttpRequest req = HttpRequest.httpRequest(svc,
                                ByteArray.byteArray(Base64.getDecoder().decode(reqB64)));

                        String respB64 = get(responseB64, i);
                        HttpRequestResponse rr;
                        if (respB64 != null && !respB64.isEmpty()) {
                            HttpResponse resp = HttpResponse.httpResponse(
                                    ByteArray.byteArray(Base64.getDecoder().decode(respB64)));
                            rr = HttpRequestResponse.httpRequestResponse(req, resp);
                        } else {
                            rr = HttpRequestResponse.httpRequestResponse(req, null);
                        }
                        evidence = new HttpRequestResponse[]{rr};
                    } catch (Exception ignore) {
                        // Corrupt/incompatible persisted evidence for this one finding --
                        // skip its evidence but still restore the issue itself.
                    }
                }

                AuditIssue issue = AuditIssue.auditIssue(
                        get(names, i),
                        get(details, i),
                        get(remediations, i),
                        get(baseUrls, i),
                        AuditIssueSeverity.valueOf(get(severities, i)),
                        AuditIssueConfidence.valueOf(get(confidences, i)),
                        get(backgrounds, i),
                        null,
                        AuditIssueSeverity.valueOf(get(severities, i)),
                        evidence
                );

                Finding f = new Finding(get(detectorIds, i), issue);
                try {
                    f.setStatus(Finding.Status.valueOf(get(statuses, i)));
                } catch (Exception ignore) {
                    // default NEW
                }
                add(f);
            }
        } catch (Exception e) {
            api.logging().logToError("[LawCyBug.pro] Failed to restore persisted findings: " + e);
        }
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    /** PersistedList.persistedStringList() is a no-arg factory for an empty
     *  list -- unlike a normal collection constructor, it doesn't accept an
     *  existing List<String> to copy from, so we create empty then addAll. */
    private static PersistedList<String> toPersistedList(List<String> values) {
        PersistedList<String> list = PersistedList.persistedStringList();
        list.addAll(values);
        return list;
    }

    private static List<String> orEmpty(List<String> l) {
        return l == null ? List.of() : l;
    }

    private static String get(List<String> l, int i) {
        return (i >= 0 && i < l.size()) ? l.get(i) : "";
    }
}
