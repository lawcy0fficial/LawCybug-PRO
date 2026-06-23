package pro.lawcybug.scanner.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Watches the FindingsStore as findings arrive and looks for pairs that,
 * together, form a known attack CHAIN rather than two unrelated bugs --
 * e.g. an Open Redirect plus an OAuth flow on the same host is far more
 * interesting together (redirect_uri hijack -> token theft) than either
 * alone, and is exactly the kind of finding high-payout bounty reports
 * lead with.
 *
 * Deliberately conservative: only raises a chain finding for known,
 * named chain templates (not a generic "these two findings share a
 * host" correlation, which would be noise), and only once per host per
 * template so a chatty scan doesn't spam ten near-duplicate chain
 * issues for the same underlying pair.
 *
 * This does NOT replace the individual findings -- both originals still
 * stand on their own. The chain issue is additive: a third, higher-level
 * issue that exists specifically to tell the analyst "look at these two
 * together first."
 */
public final class FindingsCorrelator {

    /** One named, directional chain template: if a finding from `fromDetectorId`
     *  and a finding from `toDetectorId` both exist for the same host, raise a
     *  chain finding describing the combined impact. */
    private record ChainTemplate(String fromDetectorId, String toDetectorId,
                                  String chainName, String narrativeHtml, AuditIssueSeverity severity) {
    }

    private static final List<ChainTemplate> TEMPLATES = List.of(
            new ChainTemplate(
                    "redirect.open", "oauth-security",
                    "Open Redirect → OAuth Token/Code Theft",
                    "<p>This host has both an <b>Open Redirect</b> finding and an "
                            + "<b>OAuth/OIDC</b> finding. If the open-redirect endpoint can be used as (or "
                            + "chained into) the OAuth <code>redirect_uri</code> -- directly, or via a "
                            + "whitelisted callback host that itself redirects further -- an attacker can "
                            + "craft an authorization URL that completes the OAuth flow and then bounces the "
                            + "resulting code/token to an attacker-controlled destination, leading directly "
                            + "to account takeover. This requires manual confirmation: verify the open-redirect "
                            + "endpoint is actually reachable as a valid redirect_uri value (exact match, "
                            + "registered subdomain, or path-based open redirect on a registered host).</p>",
                    AuditIssueSeverity.HIGH
            ),
            new ChainTemplate(
                    "oauth-security", "authn.account_takeover.token_replay",
                    "OAuth Flaw → Account Takeover (Token Replay)",
                    "<p>This host has both an <b>OAuth/OIDC</b> finding and a confirmed "
                            + "<b>token replay</b> finding (a reset/verification token that doesn't enforce "
                            + "single use). Combined, an OAuth flow weakness that exposes a code/token "
                            + "(missing state, loose redirect_uri, implicit flow) plus a backend that allows "
                            + "that same class of token to be replayed multiple times substantially raises "
                            + "the odds a leaked token remains usable even after the legitimate user has "
                            + "completed their own flow.</p>",
                    AuditIssueSeverity.HIGH
            ),
            new ChainTemplate(
                    "business-logic-abuse", "privesc-chain",
                    "Mass Assignment → Privilege Escalation (Confirmed Chain)",
                    "<p>This host has both a <b>Business Logic Abuse</b> finding and a confirmed "
                            + "<b>Privilege Escalation</b> finding. Together these suggest a systemic lack of "
                            + "server-side field/value validation across multiple endpoints, not an isolated "
                            + "one-off bug -- worth a broader manual review of every write endpoint on this "
                            + "host for the same class of issue, rather than treating each as independent.</p>",
                    AuditIssueSeverity.HIGH
            ),
            new ChainTemplate(
                    "privesc-chain", "bola-cross-identity",
                    "Privilege Escalation → Full BOLA Compromise",
                    "<p>This host has both a confirmed <b>Privilege Escalation</b> finding and a confirmed "
                            + "<b>Cross-Identity BOLA</b> finding. An attacker who can self-escalate privileges "
                            + "AND access other users' objects without authorization can likely combine both "
                            + "to reach full horizontal+vertical compromise: escalate to admin, then access "
                            + "every other user's data via the same object-reference pattern already confirmed "
                            + "vulnerable. Prioritize this pairing for write-up -- it's the difference between "
                            + "\"one user's IDOR\" and \"the entire dataset.\"</p>",
                    AuditIssueSeverity.HIGH
            ),
            new ChainTemplate(
                    "graphql-security", "bola-cross-identity",
                    "GraphQL Introspection → Cross-Identity BOLA on Node IDs",
                    "<p>This host has both a <b>GraphQL Security</b> finding (introspection/schema exposure) "
                            + "and a confirmed <b>Cross-Identity BOLA</b> finding. Introspection reveals exactly "
                            + "which node types and ID-shaped fields exist; combined with confirmed BOLA on this "
                            + "host's object references, an attacker can use the introspected schema as a "
                            + "lookup table to systematically enumerate every node type worth testing for the "
                            + "same authorization gap, rather than guessing.</p>",
                    AuditIssueSeverity.MEDIUM
            )
    );

    private final FindingsStore findingsStore;
    private final MontoyaApi api;

    // host -> set of detector ids with at least one finding, for fast template matching
    private final Map<String, Set<String>> detectorIdsByHost = new ConcurrentHashMap<>();
    // host -> set of chain template names already raised, so we never duplicate
    private final Map<String, Set<String>> raisedChainsByHost = new ConcurrentHashMap<>();
    // host -> detectorId -> most recent evidence, for building the chain issue's evidence list
    private final Map<String, Map<String, HttpRequestResponse>> evidenceByHost = new ConcurrentHashMap<>();

    public FindingsCorrelator(FindingsStore findingsStore, MontoyaApi api) {
        this.findingsStore = findingsStore;
        this.api = api;
        findingsStore.addListener(this::onFinding);
    }

    private void onFinding(Finding finding) {
        try {
            AuditIssue issue = finding.issue();
            String host = hostOf(issue);
            if (host == null) return;

            detectorIdsByHost.computeIfAbsent(host, h -> ConcurrentHashMap.newKeySet())
                    .add(finding.detectorId());

            List<HttpRequestResponse> evidence = issue.requestResponses();
            if (evidence != null && !evidence.isEmpty()) {
                evidenceByHost.computeIfAbsent(host, h -> new ConcurrentHashMap<>())
                        .put(finding.detectorId(), evidence.get(0));
            }

            checkTemplatesForHost(host);
        } catch (Exception e) {
            api.logging().logToError("[LawCyBug.pro] FindingsCorrelator failed on new finding: " + e);
        }
    }

    private void checkTemplatesForHost(String host) {
        Set<String> presentIds = detectorIdsByHost.getOrDefault(host, Set.of());
        Set<String> raised = raisedChainsByHost.computeIfAbsent(host, h -> ConcurrentHashMap.newKeySet());

        for (ChainTemplate template : TEMPLATES) {
            if (raised.contains(template.chainName())) continue;
            if (presentIds.contains(template.fromDetectorId()) && presentIds.contains(template.toDetectorId())) {
                raiseChainFinding(host, template);
                raised.add(template.chainName());
            }
        }
    }

    private void raiseChainFinding(String host, ChainTemplate template) {
        Map<String, HttpRequestResponse> evidenceMap = evidenceByHost.getOrDefault(host, Map.of());
        List<HttpRequestResponse> evidence = new ArrayList<>();
        HttpRequestResponse fromEv = evidenceMap.get(template.fromDetectorId());
        HttpRequestResponse toEv = evidenceMap.get(template.toDetectorId());
        if (fromEv != null) evidence.add(fromEv);
        if (toEv != null) evidence.add(toEv);

        String baseUrl = fromEv != null ? fromEv.request().url()
                : (toEv != null ? toEv.request().url() : "https://" + host + "/");

        AuditIssue chainIssue = IssueFactory.build(
                "[CHAIN] " + template.chainName(),
                template.narrativeHtml()
                        + IssueFactory.evidenceParagraph("Host", host)
                        + "<p>Component findings: <code>" + IssueFactory.escapeHtml(template.fromDetectorId())
                        + "</code> + <code>" + IssueFactory.escapeHtml(template.toDetectorId()) + "</code></p>",
                "<p>See the remediation guidance on each individual component finding. This chain "
                        + "finding exists to flag that the two should be reviewed and reported together, "
                        + "since their combined impact is materially higher than either alone.</p>",
                baseUrl,
                template.severity(),
                AuditIssueConfidence.TENTATIVE,
                "<p>Attack-chain correlation is template-based pattern matching on detector IDs sharing "
                        + "a host -- it does NOT verify the components are actually exploitable together "
                        + "(e.g. that the open redirect is genuinely reachable as this OAuth client's "
                        + "redirect_uri). Always manually confirm the chain before reporting it as such.</p>",
                evidence.toArray(new HttpRequestResponse[0])
        );

        findingsStore.add(new Finding("findings-correlator", chainIssue));
    }

    private String hostOf(AuditIssue issue) {
        List<HttpRequestResponse> evidence = issue.requestResponses();
        if (evidence != null && !evidence.isEmpty() && evidence.get(0).request() != null
                && evidence.get(0).request().httpService() != null) {
            return evidence.get(0).request().httpService().host();
        }
        // Fallback: parse host out of baseUrl() if there's no evidence request attached.
        try {
            return java.net.URI.create(issue.baseUrl()).getHost();
        } catch (Exception e) {
            return null;
        }
    }
}
