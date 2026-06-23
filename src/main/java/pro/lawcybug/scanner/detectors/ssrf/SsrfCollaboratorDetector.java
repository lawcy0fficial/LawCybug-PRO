package pro.lawcybug.scanner.detectors.ssrf;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.ActiveDetector;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.Finding;
import pro.lawcybug.scanner.core.IssueFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Server-Side Request Forgery detection via genuine out-of-band
 * confirmation using Burp Collaborator. A DNS or HTTP callback to a
 * unique, attacker-controlled subdomain is essentially unforgeable
 * evidence that the target server made an outbound connection as a
 * result of our payload. Confirmed issues are added to the site map
 * and FindingsStore from a scheduled poll; analyze() always returns
 * an empty list immediately.
 */
public final class SsrfCollaboratorDetector implements ActiveDetector {

    public static final String ID = "ssrf.collaborator_oob";

    private static final ScheduledExecutorService POLLER =
            Executors.newScheduledThreadPool(2, r -> {
                Thread t = new Thread(r, "lawcybug-ssrf-poller");
                t.setDaemon(true);
                return t;
            });

    private static final List<String> LIKELY_PARAM_HINTS = List.of(
            "url", "uri", "link", "src", "source", "callback", "webhook", "redirect",
            "next", "return", "dest", "destination", "target", "host", "domain",
            "feed", "fetch", "proxy", "image", "img", "file", "path", "site", "out", "continue"
    );

    @Override public String id()          { return ID; }
    @Override public String displayName() { return "SSRF - Collaborator Out-of-Band"; }
    @Override public String description() { return "Sends Collaborator-tagged URL payloads and confirms SSRF only on a real correlated DNS/HTTP callback."; }
    @Override public String category()    { return "SSRF"; }

    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse base,
                                     AuditInsertionPoint insertionPoint) {
        if (!ctx.settings().isCollaboratorEnabled()) return List.of();
        CollaboratorClient collaborator = ctx.collaboratorClient();
        if (collaborator == null) return List.of();

        boolean likelyCandidate = LIKELY_PARAM_HINTS.stream()
                .anyMatch(h -> insertionPoint.name().toLowerCase(Locale.ROOT).contains(h));
        // ~15% random sampling for non-obvious params so nothing is completely missed
        if (!likelyCandidate && Math.random() > 0.15) return List.of();

        String correlationTag = "ip-" + Integer.toHexString(insertionPoint.name().hashCode())
                + "-" + Integer.toHexString(base.request().url().hashCode());

        // generatePayload(customData) embeds our tag in the payload's metadata,
        // but to retrieve only THIS payload's interactions later we must keep
        // the returned CollaboratorPayload object itself -- interactionPayloadFilter
        // matches against a specific payload instance, not an arbitrary string.
        CollaboratorPayload payload = collaborator.generatePayload(correlationTag);
        String domain = payload.toString();

        for (String variant : List.of(
                "http://" + domain + "/",
                "https://" + domain + "/",
                "//" + domain + "/",
                domain)) {
            ctx.api().http().sendRequest(
                    insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(variant)));
        }

        String baseUrl  = base.request().url();
        String ipName   = insertionPoint.name();

        for (int delaySec : new int[]{5, 15, 35}) {
            POLLER.schedule(
                    () -> pollAndReport(ctx, collaborator, payload, baseUrl, ipName),
                    delaySec, TimeUnit.SECONDS);
        }
        return List.of();
    }

    private void pollAndReport(DetectorContext ctx,
                                CollaboratorClient collaborator,
                                CollaboratorPayload payload,
                                String baseUrl,
                                String insertionPointName) {
        try {
            List<Interaction> interactions =
                    collaborator.getInteractions(InteractionFilter.interactionPayloadFilter(payload.toString()));
            if (interactions.isEmpty()) return;

            StringBuilder detail = new StringBuilder();
            detail.append(IssueFactory.evidenceParagraph("Insertion point", insertionPointName));
            detail.append(IssueFactory.evidenceParagraph("Collaborator payload", payload.toString()));
            for (Interaction i : interactions) {
                detail.append(IssueFactory.evidenceParagraph("Type", i.type().toString()));
                detail.append(IssueFactory.evidenceParagraph("Client IP", String.valueOf(i.clientIp())));
                detail.append(IssueFactory.evidenceParagraph("Time", String.valueOf(i.timeStamp())));
            }

            AuditIssue issue = IssueFactory.build(
                    "Server-Side Request Forgery (OOB Confirmed)",
                    detail.toString(),
                    "Allow-list outbound destinations by scheme, host and port. Block requests to "
                            + "link-local/private/metadata ranges at the network layer. Disable unused "
                            + "schemes and avoid following redirects from user-supplied URLs.",
                    baseUrl,
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.CERTAIN,
                    "A unique Collaborator payload received a real DNS/HTTP interaction from "
                            + "infrastructure related to the target, directly proving the server made an "
                            + "outbound connection to attacker-controlled infrastructure."
            );
            ctx.api().siteMap().add(issue);
            ctx.findingsStore().add(new Finding(ID, issue));
        } catch (Exception e) {
            ctx.api().logging().logToError("[LawCyBug.pro] SSRF poll error: " + e);
        }
    }
}
