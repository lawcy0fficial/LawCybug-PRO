package pro.lawcybug.scanner.workflow;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Executes a small, named sequence of HTTP steps where later steps can
 * reference values extracted from earlier steps' responses (e.g. a created
 * resource's ID) and can be replayed under a different {@link SessionIdentity}.
 * This is the mechanism that turns independent single-request checks into
 * real attack chains: register -> confirm -> reset -> takeover,
 * create-resource -> switch-identity -> access-as-attacker, etc.
 *
 * Extraction uses a tiny JSONPath-ish dotted-key syntax against the parsed
 * response body (via {@link JsonLite}), e.g. "id" or "data.user.id".
 */
public final class WorkflowEngine {

    private final MontoyaApi api;
    private final ChainGuard chainGuard;

    public WorkflowEngine(MontoyaApi api) {
        this(api, null);
    }

    public WorkflowEngine(MontoyaApi api, ChainGuard chainGuard) {
        this.api = api;
        this.chainGuard = chainGuard;
    }

    /** One step: build a request from current variables, send it, optionally extract new variables. */
    public static final class Step {
        final String name;
        final Function<Map<String, String>, HttpRequest> requestBuilder;
        final String extractVarName;   // nullable
        final String extractJsonPath;  // nullable, dotted path e.g. "data.id"
        SessionIdentity identityOverride; // nullable -- defaults to chain's current identity
        boolean mutating = false;

        public Step(String name, Function<Map<String, String>, HttpRequest> requestBuilder) {
            this(name, requestBuilder, null, null);
        }

        public Step(String name, Function<Map<String, String>, HttpRequest> requestBuilder,
                    String extractVarName, String extractJsonPath) {
            this.name = name;
            this.requestBuilder = requestBuilder;
            this.extractVarName = extractVarName;
            this.extractJsonPath = extractJsonPath;
        }

        public Step asIdentity(SessionIdentity identity) {
            this.identityOverride = identity;
            return this;
        }

        /** Mark this step as state-mutating (refund, role-change, password-reset, coupon-apply, etc.).
         *  Subject to Safe Mode -- see {@link pro.lawcybug.scanner.workflow.ChainGuard}. */
        public Step asMutating() {
            this.mutating = true;
            return this;
        }
    }

    public static final class StepResult {
        public final String stepName;
        public final HttpRequestResponse requestResponse;
        public final boolean succeeded;
        public final boolean skippedBySafeMode;

        StepResult(String stepName, HttpRequestResponse requestResponse, boolean succeeded) {
            this(stepName, requestResponse, succeeded, false);
        }

        StepResult(String stepName, HttpRequestResponse requestResponse, boolean succeeded, boolean skippedBySafeMode) {
            this.stepName = stepName;
            this.requestResponse = requestResponse;
            this.succeeded = succeeded;
            this.skippedBySafeMode = skippedBySafeMode;
        }
    }

    public static final class ChainResult {
        public final java.util.List<StepResult> steps = new java.util.ArrayList<>();
        public final Map<String, String> variables = new LinkedHashMap<>();

        public StepResult last() {
            return steps.isEmpty() ? null : steps.get(steps.size() - 1);
        }

        public StepResult byName(String name) {
            return steps.stream().filter(s -> s.stepName.equals(name)).findFirst().orElse(null);
        }
    }

    /**
     * Runs the given steps in order under the given default identity. If a
     * step throws or returns no response, the chain stops early (partial
     * results are still returned -- callers should check steps.size()
     * against the expected step count).
     */
    public ChainResult run(java.util.List<Step> steps, SessionIdentity defaultIdentity) {
        ChainResult result = new ChainResult();
        if (chainGuard != null) {
            chainGuard.beginChain();
        }
        for (Step step : steps) {
            try {
                HttpRequest built = step.requestBuilder.apply(result.variables);
                SessionIdentity identity = step.identityOverride != null ? step.identityOverride : defaultIdentity;
                if (identity != null) {
                    built = identity.stamp(built);
                }

                if (chainGuard != null && !chainGuard.allow(built.method(), step.mutating)) {
                    result.steps.add(new StepResult(step.name, null, false, true));
                    break;
                }

                HttpRequestResponse rr = api.http().sendRequest(built);
                boolean ok = rr.response() != null;
                result.steps.add(new StepResult(step.name, rr, ok));
                if (!ok) break;

                if (step.extractVarName != null && step.extractJsonPath != null) {
                    String extracted = extractJsonPath(rr.response().bodyToString(), step.extractJsonPath);
                    if (extracted != null) {
                        result.variables.put(step.extractVarName, extracted);
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[LawCyBug.pro] workflow step '" + step.name + "' failed: " + e);
                break;
            }
        }
        return result;
    }

    /** Simple variable substitution: replaces {{varName}} in a template string. */
    public static String substitute(String template, Map<String, String> variables) {
        if (template == null) return null;
        String result = template;
        for (Map.Entry<String, String> entry : variables.entrySet()) {
            result = result.replace("{{" + entry.getKey() + "}}", entry.getValue());
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private String extractJsonPath(String body, String dottedPath) {
        try {
            Object root = JsonLite.parse(body.trim());
            Object current = root;
            for (String part : dottedPath.split("\\.")) {
                if (current instanceof Map) {
                    current = ((Map<String, Object>) current).get(part);
                } else {
                    return null;
                }
            }
            return current == null ? null : String.valueOf(current);
        } catch (Exception e) {
            // Fallback: cheap regex extraction for non-strict JSON / partial bodies,
            // e.g. "id":123 or "id":"abc-123" anywhere in the body.
            Pattern p = Pattern.compile("\"" + Pattern.quote(lastSegment(dottedPath))
                    + "\"\\s*:\\s*\"?([\\w.\\-]+)\"?");
            Matcher m = p.matcher(body == null ? "" : body);
            return m.find() ? m.group(1) : null;
        }
    }

    private String lastSegment(String dottedPath) {
        int idx = dottedPath.lastIndexOf('.');
        return idx == -1 ? dottedPath : dottedPath.substring(idx + 1);
    }
}
