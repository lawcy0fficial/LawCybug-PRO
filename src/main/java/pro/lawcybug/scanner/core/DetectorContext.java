package pro.lawcybug.scanner.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import pro.lawcybug.scanner.workflow.ChainGuard;
import pro.lawcybug.scanner.workflow.IdentityRegistry;
import pro.lawcybug.scanner.workflow.ObjectGraph;
import pro.lawcybug.scanner.workflow.ResponseSimilarityEngine;
import pro.lawcybug.scanner.workflow.WorkflowEngine;

/**
 * Shared context handed to every detector on every invocation.
 * Holds a reference to the Montoya API, the global scan settings,
 * the findings store (for live UI updates) and a single shared
 * Collaborator client used by every out-of-band detector (SSRF,
 * blind XXE, blind injection, etc.) so we don't burn a fresh
 * Collaborator client per request.
 *
 * Also holds the multi-user / stateful workflow components shared
 * across all detectors that need them (BOLA/IDOR cross-identity
 * replay, ATO chains, business-logic chains): one ObjectGraph and one
 * IdentityRegistry per extension instance, so e.g. a resource ID seen
 * by the passive object-discovery detector is immediately available
 * to the active BOLA-replay detector without any wiring on the
 * detector author's part.
 */
public final class DetectorContext {

    private final MontoyaApi api;
    private final ScanSettings settings;
    private final FindingsStore findingsStore;
    private final CollaboratorClient collaboratorClient;
    private final ObjectGraph objectGraph;
    private final IdentityRegistry identityRegistry;
    private final ResponseSimilarityEngine similarityEngine;
    private final WorkflowEngine workflowEngine;
    private final ChainGuard chainGuard;

    public DetectorContext(MontoyaApi api,
                            ScanSettings settings,
                            FindingsStore findingsStore,
                            CollaboratorClient collaboratorClient) {
        this.api = api;
        this.settings = settings;
        this.findingsStore = findingsStore;
        this.collaboratorClient = collaboratorClient;
        this.objectGraph = new ObjectGraph();
        this.identityRegistry = new IdentityRegistry();
        this.similarityEngine = new ResponseSimilarityEngine();
        this.chainGuard = new ChainGuard(settings);
        this.workflowEngine = new WorkflowEngine(api, chainGuard);
    }

    public MontoyaApi api() {
        return api;
    }

    public ScanSettings settings() {
        return settings;
    }

    public FindingsStore findingsStore() {
        return findingsStore;
    }

    /**
     * May be null if Collaborator is unavailable (e.g. Burp Community
     * Edition without a configured Collaborator server, or offline
     * private Collaborator server not configured). Detectors that rely
     * on it MUST null-check before use and degrade gracefully.
     */
    public CollaboratorClient collaboratorClient() {
        return collaboratorClient;
    }

    public ObjectGraph objectGraph() {
        return objectGraph;
    }

    public IdentityRegistry identityRegistry() {
        return identityRegistry;
    }

    public ResponseSimilarityEngine similarityEngine() {
        return similarityEngine;
    }

    public WorkflowEngine workflowEngine() {
        return workflowEngine;
    }

    public ChainGuard chainGuard() {
        return chainGuard;
    }
}
