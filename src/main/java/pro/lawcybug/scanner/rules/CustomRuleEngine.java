package pro.lawcybug.scanner.rules;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import pro.lawcybug.scanner.core.ActiveDetector;
import pro.lawcybug.scanner.core.DetectorContext;
import pro.lawcybug.scanner.core.IssueFactory;
import pro.lawcybug.scanner.core.PassiveDetector;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Pattern;

/**
 * JSON-based custom rule engine. Users can drop a JSON file anywhere
 * and load it via the Rules tab. Rules support:
 *
 *  type: "passive" | "active"
 *  name: display name of the issue to report
 *  severity: "high" | "medium" | "low" | "info"
 *  confidence: "certain" | "firm" | "tentative"
 *  description: background text
 *  remediation: remediation text
 *  conditions:
 *    For passive:
 *      - { target: "response_body" | "response_header" | "request_header", pattern: "regex" }
 *    For active:
 *      - { payload: "...", match: "response_body", pattern: "regex" }
 *      - { payload: "...", status: 200 }          -- check status code
 *      - { condition: "and" | "or" }              -- combine conditions
 *
 * Example rule JSON (single-rule file):
 * {
 *   "name": "Internal IP Disclosure",
 *   "type": "passive",
 *   "severity": "medium",
 *   "confidence": "firm",
 *   "description": "An RFC1918 IP address was found in the response.",
 *   "remediation": "Remove internal IPs from API responses.",
 *   "conditions": [
 *     { "target": "response_body", "pattern": "\\b(10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}|172\\.(1[6-9]|2[0-9]|3[01])\\.[0-9]{1,3}\\.[0-9]{1,3}|192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3})\\b" }
 *   ]
 * }
 *
 * Or a rules-array file: [ { ...rule1... }, { ...rule2... } ]
 */
public final class CustomRuleEngine implements PassiveDetector, ActiveDetector {

    public static final String ID = "rules.custom";

    /**
     * Rule packs shipped inside the extension jar (src/main/resources/rules/).
     * Loaded automatically on startup via {@link #loadBundledRules()} so they
     * run "internally" with no manual import step. Add new bundled packs here
     * AND drop the matching .json file in src/main/resources/rules/.
     */
    private static final String[] BUNDLED_RULE_RESOURCES = {
            "/rules/01-p1-advanced-rules.json",
            "/rules/02-p1-mega-ruleset.json",
            "/rules/03-p1-web3-cloud-cms-webserver-rules.json",
            "/rules/04-p1-mobile-iot-mq-cicd-rules.json"
    };

    private static final String SOURCE_MANUAL = "manual";
    private static final String SOURCE_BUNDLED_PREFIX = "bundled:";

    private final List<Rule> rules = new ArrayList<>();

    @Override public String id()          { return ID; }
    @Override public String displayName() { return "Custom Rules (JSON)"; }
    @Override public String description() { return "User-defined passive/active scan rules loaded from JSON files."; }
    @Override public String category()    { return "Custom"; }

    public void loadFromJson(String jsonText) throws Exception {
        loadFromJson(jsonText, SOURCE_MANUAL);
    }

    public void loadFromJson(String jsonText, String source) throws Exception {
        List<Map<String, Object>> rawRules = MiniJson.parseRulesList(jsonText);
        for (Map<String, Object> raw : rawRules) {
            Rule r = Rule.fromMap(raw);
            r.source = source;
            rules.add(r);
        }
    }

    public void loadFromFile(Path path) throws Exception {
        String text = Files.readString(path, StandardCharsets.UTF_8);
        loadFromJson(text, SOURCE_MANUAL);
    }

    /**
     * Loads one rule pack bundled inside the extension jar via the classloader
     * (src/main/resources/rules/*.json -&gt; classpath root /rules/*.json).
     */
    public int loadFromResource(String resourcePath) throws Exception {
        try (var in = CustomRuleEngine.class.getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new java.io.FileNotFoundException("Bundled rule resource not found on classpath: " + resourcePath);
            }
            String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            int before = rules.size();
            String fileName = resourcePath.substring(resourcePath.lastIndexOf('/') + 1);
            loadFromJson(text, SOURCE_BUNDLED_PREFIX + fileName);
            return rules.size() - before;
        }
    }

    /**
     * Loads every rule pack listed in {@link #BUNDLED_RULE_RESOURCES}. One bad/missing
     * file doesn't stop the rest — failures are collected and returned so the caller
     * can log/display them instead of the whole extension silently shipping zero rules.
     */
    public BundleLoadResult loadBundledRules() {
        int filesLoaded = 0;
        int rulesLoaded = 0;
        List<String> errors = new ArrayList<>();
        for (String resource : BUNDLED_RULE_RESOURCES) {
            try {
                rulesLoaded += loadFromResource(resource);
                filesLoaded++;
            } catch (Exception e) {
                errors.add(resource + " -> " + e.getMessage());
            }
        }
        return new BundleLoadResult(filesLoaded, BUNDLED_RULE_RESOURCES.length, rulesLoaded, errors);
    }

    public void clearRules() {
        rules.clear();
    }

    /** Removes only rules loaded via "Load from editor" / "Load from .json file" — bundled packs are untouched. */
    public void clearManualRules() {
        rules.removeIf(r -> SOURCE_MANUAL.equals(r.source));
    }

    /** Removes only the bundled rule packs (e.g. before {@link #loadBundledRules()} re-loads them fresh). */
    public void clearBundledRules() {
        rules.removeIf(r -> r.source != null && r.source.startsWith(SOURCE_BUNDLED_PREFIX));
    }

    public int ruleCount() {
        return rules.size();
    }

    public int bundledRuleCount() {
        return (int) rules.stream().filter(r -> r.source != null && r.source.startsWith(SOURCE_BUNDLED_PREFIX)).count();
    }

    public int manualRuleCount() {
        return (int) rules.stream().filter(r -> SOURCE_MANUAL.equals(r.source)).count();
    }

    public List<Rule> getRules() {
        return Collections.unmodifiableList(rules);
    }

    /** Result of {@link #loadBundledRules()} — how many packs/rules loaded, and any per-file failures. */
    public record BundleLoadResult(int filesLoaded, int filesAttempted, int rulesLoaded, List<String> errors) {
        public boolean allOk() { return errors.isEmpty(); }
    }

    // ─── PassiveDetector ─────────────────────────────────────────────────────
    @Override
    public List<AuditIssue> analyze(DetectorContext ctx, HttpRequestResponse base) {
        List<AuditIssue> issues = new ArrayList<>();
        if (base.response() == null) return issues;

        for (Rule rule : rules) {
            if (!"passive".equalsIgnoreCase(rule.type)) continue;
            try {
                if (ruleMatchesPassive(rule, base)) {
                    issues.add(buildIssue(rule, base.request().url(), base));
                }
            } catch (Exception e) {
                ctx.api().logging().logToError("[LawCyBug.pro] Custom rule '" + rule.name + "' error: " + e);
            }
        }
        return issues;
    }

    // ─── ActiveDetector ──────────────────────────────────────────────────────
    @Override
    public List<AuditIssue> analyze(DetectorContext ctx,
                                     HttpRequestResponse base,
                                     AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();

        for (Rule rule : rules) {
            if (!"active".equalsIgnoreCase(rule.type)) continue;
            try {
                for (Condition cond : rule.conditions) {
                    if (cond.payload == null) continue;
                    HttpRequestResponse result = ctx.api().http().sendRequest(
                            insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(cond.payload)));
                    if (result.response() == null) continue;
                    if (conditionMatchesActive(cond, result)) {
                        issues.add(buildIssue(rule, base.request().url(), result));
                        break;
                    }
                }
            } catch (Exception e) {
                ctx.api().logging().logToError("[LawCyBug.pro] Custom active rule '" + rule.name + "' error: " + e);
            }
        }
        return issues;
    }

    // ─── Matching helpers ────────────────────────────────────────────────────
    private boolean ruleMatchesPassive(Rule rule, HttpRequestResponse base) {
        for (Condition cond : rule.conditions) {
            boolean match = switch (cond.target.toLowerCase(Locale.ROOT)) {
                case "response_body"   -> cond.compiledPattern != null && cond.compiledPattern.matcher(base.response().bodyToString()).find();
                case "response_header" -> cond.compiledPattern != null && base.response().headers().stream().anyMatch(h -> cond.compiledPattern.matcher(h.name() + ": " + h.value()).find());
                case "request_header"  -> cond.compiledPattern != null && base.request().headers().stream().anyMatch(h -> cond.compiledPattern.matcher(h.name() + ": " + h.value()).find());
                default -> false;
            };
            if (!match) return false; // implicit AND across conditions
        }
        return !rule.conditions.isEmpty();
    }

    private boolean conditionMatchesActive(Condition cond, HttpRequestResponse result) {
        if ("response_body".equalsIgnoreCase(cond.match) && cond.compiledPattern != null) {
            return cond.compiledPattern.matcher(result.response().bodyToString()).find();
        }
        if ("response_header".equalsIgnoreCase(cond.match) && cond.compiledPattern != null) {
            return result.response().headers().stream()
                    .anyMatch(h -> cond.compiledPattern.matcher(h.name() + ": " + h.value()).find());
        }
        if ("status".equalsIgnoreCase(cond.match) && cond.expectedStatus > 0) {
            return result.response().statusCode() == cond.expectedStatus;
        }
        return false;
    }

    private AuditIssue buildIssue(Rule rule, String url, HttpRequestResponse evidence) {
        return IssueFactory.build(
                "Custom Rule: " + rule.name,
                "<p>" + IssueFactory.escapeHtml(rule.description) + "</p>",
                rule.remediation,
                url, rule.severity, rule.confidence, rule.description, evidence);
    }

    // ─── Data model ──────────────────────────────────────────────────────────
    public static final class Rule {
        public String type;
        public String name;
        public String description;
        public String remediation;
        public AuditIssueSeverity severity;
        public AuditIssueConfidence confidence;
        public List<Condition> conditions;
        /** "manual" (loaded via the Rules tab) or "bundled:&lt;filename&gt;" (shipped in the jar). */
        public String source = "manual";

        static Rule fromMap(Map<String, Object> m) {
            Rule r = new Rule();
            r.type        = str(m, "type", "passive");
            r.name        = str(m, "name", "Unnamed Rule");
            r.description = str(m, "description", "");
            r.remediation = str(m, "remediation", "");
            r.severity    = parseSeverity(str(m, "severity", "medium"));
            r.confidence  = parseConfidence(str(m, "confidence", "tentative"));
            r.conditions  = new ArrayList<>();
            Object condRaw = m.get("conditions");
            if (condRaw instanceof List<?> condList) {
                for (Object co : condList) {
                    if (co instanceof Map<?,?> condMap) {
                        r.conditions.add(Condition.fromMap(condMap));
                    }
                }
            }
            return r;
        }

        private static String str(Map<String, Object> m, String key, String def) {
            Object v = m.get(key);
            return v != null ? String.valueOf(v) : def;
        }
    }

    public static final class Condition {
        public String  target;           // passive: response_body / response_header / request_header
        public String  pattern;          // regex string
        public Pattern compiledPattern;
        public String  payload;          // active: payload to inject
        public String  match;            // active: what to check (response_body / status)
        public int     expectedStatus;   // active: expected HTTP status code

        @SuppressWarnings("unchecked")
        static Condition fromMap(Map<?,?> m) {
            Condition c = new Condition();
            c.target   = getString(m, "target", "response_body");
            c.pattern  = getString(m, "pattern", null);
            c.payload  = getString(m, "payload", null);
            c.match    = getString(m, "match", "response_body");
            String statusStr = getString(m, "status", "0");
            try { c.expectedStatus = Integer.parseInt(statusStr); } catch (NumberFormatException ignore) {}
            if (c.pattern != null) {
                try { c.compiledPattern = Pattern.compile(c.pattern); } catch (Exception ignore) {}
            }
            return c;
        }

        private static String getString(Map<?,?> m, String key, String def) {
            Object v = m.get(key);
            return v != null ? String.valueOf(v) : def;
        }
    }

    private static AuditIssueSeverity parseSeverity(String s) {
        return switch (s.toLowerCase(Locale.ROOT)) {
            case "high" -> AuditIssueSeverity.HIGH;
            case "low"  -> AuditIssueSeverity.LOW;
            case "info" -> AuditIssueSeverity.INFORMATION;
            default     -> AuditIssueSeverity.MEDIUM;
        };
    }

    private static AuditIssueConfidence parseConfidence(String s) {
        return switch (s.toLowerCase(Locale.ROOT)) {
            case "certain" -> AuditIssueConfidence.CERTAIN;
            case "firm"    -> AuditIssueConfidence.FIRM;
            default        -> AuditIssueConfidence.TENTATIVE;
        };
    }
}
