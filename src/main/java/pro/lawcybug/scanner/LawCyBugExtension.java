package pro.lawcybug.scanner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import pro.lawcybug.scanner.core.*;
import pro.lawcybug.scanner.detectors.cors.CorsDetector;
import pro.lawcybug.scanner.detectors.headers.SecurityHeadersDetector;
import pro.lawcybug.scanner.detectors.info.InfoDisclosureDetector;
import pro.lawcybug.scanner.detectors.jwt.JwtMisconfigDetector;
import pro.lawcybug.scanner.detectors.redirect.OpenRedirectDetector;
import pro.lawcybug.scanner.detectors.sqli.*;
import pro.lawcybug.scanner.detectors.ssrf.SsrfCollaboratorDetector;
import pro.lawcybug.scanner.detectors.ssrf.SstiDetector;
import pro.lawcybug.scanner.detectors.cmdi.BlindCommandInjectionDetector;
import pro.lawcybug.scanner.detectors.xss.ReflectedXssDetector;
import pro.lawcybug.scanner.detectors.idor.IdorAuthorizationDetector;
import pro.lawcybug.scanner.detectors.race.RaceConditionDetector;
import pro.lawcybug.scanner.detectors.takeover.AccountTakeoverDetector;
import pro.lawcybug.scanner.detectors.massassignment.MassAssignmentConfirmDetector;
import pro.lawcybug.scanner.detectors.authzbypass.AuthzBypassDetector;
import pro.lawcybug.scanner.rules.CustomRuleEngine;
import pro.lawcybug.scanner.ui.LawCyBugTab;

/**
 * LawCyBug.pro Burp Suite Extension — entry point.
 *
 * Burp calls initialize() once when the JAR is loaded. Everything
 * wires together here: settings, Collaborator client, detector engine,
 * all detector registrations, the UI tab, and the ScanCheck registration
 * with Burp's scanner.
 */
public final class LawCyBugExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("LawCyBug.pro Scanner");
        api.logging().logToOutput("[LawCyBug.pro] Loading v1.0.0 ...");

        // ── Core infrastructure ────────────────────────────────────────────
        ScanSettings   settings     = new ScanSettings();
        FindingsStore  findingsStore = new FindingsStore();
        new FindingsCorrelator(findingsStore, api); // self-registers as a findings listener; no reference needed

        CollaboratorClient collaborator = null;
        try {
            collaborator = api.collaborator().createClient();
        } catch (Exception e) {
            api.logging().logToOutput(
                "[LawCyBug.pro] Collaborator unavailable (Community Edition or no server configured). "
                + "OOB checks (SSRF, blind XXE) will be skipped.");
        }

        DetectorContext context = new DetectorContext(api, settings, findingsStore, collaborator);
        DetectorEngine  engine  = new DetectorEngine(context);

        // ── Register passive detectors ─────────────────────────────────────
        SecurityHeadersDetector secHeaders = new SecurityHeadersDetector();
        engine.registerPassive(secHeaders);

        InfoDisclosureDetector infoDisc = new InfoDisclosureDetector();
        engine.registerPassive(infoDisc);

        CorsDetector cors = new CorsDetector();
        engine.registerPassive(cors);    // passive facet

        JwtMisconfigDetector jwt = new JwtMisconfigDetector();
        engine.registerPassive(jwt);     // passive facet

        // ── Register active detectors ──────────────────────────────────────
        engine.registerActive(new SqlErrorBasedDetector());
        engine.registerActive(new SqlBooleanBasedDetector());
        engine.registerActive(new SqlTimeBasedDetector());
        engine.registerActive(new ReflectedXssDetector());
        engine.registerActive(new BlindCommandInjectionDetector());
        engine.registerActive(new SsrfCollaboratorDetector());
        engine.registerActive(new SstiDetector());
        engine.registerActive(new OpenRedirectDetector());
        engine.registerActive(cors);     // active facet
        engine.registerActive(jwt);      // active facet

        // ── Stateful authz / business-logic confirmation detectors ──────────
        // These cannot live in the JSON rule engine (single-request only).
        // IDOR confirmation requires settings.secondarySessionHeaderValue to
        // be configured in the Settings tab; it degrades to a silent no-op
        // (no false signal) if left blank.
        engine.registerActive(new IdorAuthorizationDetector());
        engine.registerActive(new RaceConditionDetector());
        engine.registerActive(new AccountTakeoverDetector());
        engine.registerActive(new MassAssignmentConfirmDetector());
        engine.registerActive(new AuthzBypassDetector());

        pro.lawcybug.scanner.detectors.graphql.GraphQlSecurityDetector graphQl =
                new pro.lawcybug.scanner.detectors.graphql.GraphQlSecurityDetector();
        engine.registerPassive(graphQl);
        engine.registerActive(graphQl);

        pro.lawcybug.scanner.detectors.bola.CrossIdentityBolaDetector crossBola =
                new pro.lawcybug.scanner.detectors.bola.CrossIdentityBolaDetector();
        engine.registerPassive(crossBola);
        engine.registerActive(crossBola);

        engine.registerActive(new pro.lawcybug.scanner.detectors.atochain.PrivilegeEscalationChainDetector());
        engine.registerActive(new pro.lawcybug.scanner.detectors.businesslogic.BusinessLogicAbuseDetector());

        pro.lawcybug.scanner.detectors.oauth.OAuthSecurityDetector oauth =
                new pro.lawcybug.scanner.detectors.oauth.OAuthSecurityDetector();
        engine.registerPassive(oauth);
        engine.registerActive(oauth);

        // ── Custom rule engine (passive + active) ──────────────────────────
        CustomRuleEngine ruleEngine = new CustomRuleEngine();
        engine.registerPassive(ruleEngine);
        engine.registerActive(ruleEngine);

        // Load the rule packs shipped inside this jar (src/main/resources/rules/)
        // so they run automatically with no manual import step.
        CustomRuleEngine.BundleLoadResult bundleResult = ruleEngine.loadBundledRules();
        api.logging().logToOutput(
            "[LawCyBug.pro] Bundled rules: " + bundleResult.filesLoaded() + "/" + bundleResult.filesAttempted()
            + " pack(s) loaded, " + bundleResult.rulesLoaded() + " rule(s) total."
        );
        for (String err : bundleResult.errors()) {
            api.logging().logToError("[LawCyBug.pro] Bundled rule pack failed to load: " + err);
        }

        // ── Register with Burp scanner ─────────────────────────────────────
        api.scanner().registerScanCheck(engine);

        // ── Register UI tab ────────────────────────────────────────────────
        LawCyBugTab tab = new LawCyBugTab(api, findingsStore, settings, engine, ruleEngine, context.identityRegistry());
        api.userInterface().registerSuiteTab(tab.caption(), tab.uiComponent());

        // Restore findings from a previous session (AFTER the tab above has
        // already registered its listener, so restored findings populate the
        // table through the normal store.add() path).
        findingsStore.loadPersisted(api);

        api.logging().logToOutput(
            "[LawCyBug.pro] Loaded. Active detectors: " + engine.activeDetectors().size()
            + "  Passive detectors: " + engine.passiveDetectors().size()
        );

        // ── Unload hook ────────────────────────────────────────────────────
        api.extension().registerUnloadingHandler(() -> {
            findingsStore.persist(api);
            api.logging().logToOutput("[LawCyBug.pro] Extension unloaded cleanly (findings saved).");
        });
    }
}
