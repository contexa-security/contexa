package io.contexa.showcase.workload.contexa.internal;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.service.UserEngineStatePurgeResult;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.showcase.workload.contexa.inbox.DemoInboxEmailService;
import io.contexa.showcase.workload.contexa.observation.AnalysisEventRecorder;
import io.contexa.showcase.workload.contexa.observation.DecisionRecords;
import io.contexa.showcase.workload.contexa.observation.UsageLedger;
import io.contexa.showcase.workload.contexa.observation.ModelExchanges;
import io.contexa.showcase.workload.contexa.observation.RequestReceipts;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.showcase.workload.contexa.principal.OrphanPrincipalSweeper;
import io.contexa.showcase.workload.contexa.principal.RunPrincipalService;
import io.contexa.showcase.workload.contexa.principal.SharedAccountGuard;
import io.contexa.showcase.workload.contexa.template.TemplateSnapshot;
import io.contexa.showcase.workload.contexa.template.TemplateSnapshots;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.info.BuildProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.ZoneId;
import java.util.LinkedHashMap;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Management API of control D, called only by the portal orchestrator with a signed internal context
 * (docs/showcase/ADR.md ADR-24): run principals with their template state, template snapshots, the demo inbox, the
 * evidence of one decision, and the engine configuration that goes into the execution specification.
 */
@RestController
public class ContexaInternalController {

    /**
     * @param approver the run's security administrator who approves a block release (ADR-33), not a request sender
     */
    public record PrincipalRequest(String username, String password, String employeeKey, String roleKey,
                                   String displayName, String department, String organizationId, String tenantId,
                                   TemplateSnapshot template, Boolean approver) {
    }

    public record SnapshotRequest(String username, String employeeKey, String organizationId, String tenantId) {
    }

    /** @param receivedAt when control D received the request, on D's clock; null when D no longer holds it (#44) */
    public record DecisionEvidence(String requestId, List<DecisionRecords.DecisionRecord> records,
                                   List<AnalysisEventRecorder.AnalysisEvent> events,
                                   List<UsageLedger.ModelCall> modelCalls, Instant receivedAt) {
    }

    private final RunPrincipalService principals;
    private final SharedAccountGuard sharedAccounts;
    private final OrphanPrincipalSweeper orphans;
    private final TemplateSnapshots templates;
    private final DemoInboxEmailService inbox;
    private final DecisionRecords decisions;
    private final AnalysisEventRecorder analysisEvents;
    private final UsageLedger usage;
    private final ModelExchanges exchanges;
    private final RequestReceipts receipts;
    private final ObjectProvider<TieredStrategyProperties> tieredProperties;
    private final SecurityZeroTrustProperties zeroTrust;
    private final String chatModel;
    private final String embeddingModel;
    private final int embeddingDimensions;
    private final ObjectProvider<BuildProperties> build;
    private final boolean forcedActions;
    private final Integer behaviorRetentionDays;

    public ContexaInternalController(RunPrincipalService principals, SharedAccountGuard sharedAccounts,
                                     OrphanPrincipalSweeper orphans,
                                     TemplateSnapshots templates,
                                     DemoInboxEmailService inbox, DecisionRecords decisions,
                                     AnalysisEventRecorder analysisEvents, UsageLedger usage,
                                     ModelExchanges exchanges, RequestReceipts receipts,
                                     ObjectProvider<TieredStrategyProperties> tieredProperties,
                                     SecurityZeroTrustProperties zeroTrust,
                                     @Value("${spring.ai.openai.chat.options.model:}") String chatModel,
                                     @Value("${spring.ai.openai.embedding.options.model:}") String embeddingModel,
                                     @Value("${spring.ai.openai.embedding.options.dimensions:0}") int embeddingDimensions,
                                     ObjectProvider<BuildProperties> build,
                                     @Value("${showcase.dev.forced-actions:false}") boolean forcedActions,
                                     @Value("${contexa.rag.etl.behavior.retention-days:#{null}}")
                                     Integer behaviorRetentionDays) {
        this.principals = principals;
        this.sharedAccounts = sharedAccounts;
        this.orphans = orphans;
        this.templates = templates;
        this.inbox = inbox;
        this.decisions = decisions;
        this.analysisEvents = analysisEvents;
        this.usage = usage;
        this.exchanges = exchanges;
        this.receipts = receipts;
        this.tieredProperties = tieredProperties;
        this.zeroTrust = zeroTrust;
        this.chatModel = chatModel;
        this.embeddingModel = embeddingModel;
        this.embeddingDimensions = embeddingDimensions;
        this.build = build;
        this.forcedActions = forcedActions;
        this.behaviorRetentionDays = behaviorRetentionDays;
    }

    @PostMapping("/internal/runs/{runId}/principals")
    public Map<String, Object> createPrincipal(@PathVariable("runId") String runId,
                                               @RequestBody PrincipalRequest request) {
        principals.create(new RunPrincipalService.Principal(request.username(), runId, request.employeeKey(),
                request.roleKey(), request.displayName(), request.department(), request.organizationId(),
                request.tenantId(), Boolean.TRUE.equals(request.approver())), request.password());
        int documents = request.template() == null ? 0
                : templates.importInto(request.template(), request.username(), request.organizationId(),
                request.tenantId());
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("username", request.username());
        result.put("email", request.username() + "@showcase.invalid");
        result.put("templateUser", request.template() == null ? null : request.template().templateUser());
        result.put("importedDocuments", documents);
        return result;
    }

    @DeleteMapping("/internal/runs/{runId}/principals/{username}")
    public UserEngineStatePurgeResult deletePrincipal(@PathVariable("runId") String runId,
                                                      @PathVariable("username") String username) {
        return principals.delete(username);
    }

    /** Sweeps of principals whose account is gone but whose late engine state was written after the purge. */
    /** Engine accounts other than run principals and bridge mirrors that could still sign in (P5-SEC-01). */
    @GetMapping("/internal/accounts/shared")
    public List<String> usableSharedAccounts() {
        return sharedAccounts.usableSharedAccounts();
    }

    @GetMapping("/internal/principals/orphan-sweeps")
    public OrphanPrincipalSweeper.SweepState orphanSweeps() {
        return orphans.state();
    }

    @PostMapping("/internal/templates/snapshot")
    public TemplateSnapshot snapshot(@RequestBody SnapshotRequest request) {
        return templates.export(request.username(), request.employeeKey(), request.organizationId(),
                request.tenantId());
    }

    @GetMapping("/internal/inbox/{recipient}")
    public ResponseEntity<DemoInboxEmailService.InboxCode> inbox(@PathVariable("recipient") String recipient) {
        return inbox.take(recipient).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/internal/decisions/{requestId}")
    public DecisionEvidence decision(@PathVariable("requestId") String requestId) {
        return new DecisionEvidence(requestId, decisions.byRequestId(requestId), analysisEvents.eventsOf(requestId),
                usage.callsOf(requestId), receipts.receivedAt(requestId).orElse(null));
    }

    /**
     * Every model call of a decision as it happened: prompt messages, provider request options, provider response,
     * answer, finish reason and tokens (docs/showcase/데모-재설계.md 5.1). Empty when control D no longer holds it.
     */
    @GetMapping("/internal/decisions/{requestId}/exchanges")
    public List<ModelExchanges.Exchange> exchanges(@PathVariable("requestId") String requestId) {
        return exchanges.of(requestId);
    }

    /** The normalised prompt of a decision (PromptFingerprint), compared by the isolation smoke (T6, T7). */
    @GetMapping("/internal/decisions/{requestId}/prompt")
    public ResponseEntity<Map<String, String>> prompt(@PathVariable("requestId") String requestId) {
        String prompt = usage.promptOf(requestId);
        return prompt == null ? ResponseEntity.notFound().build()
                : ResponseEntity.ok(Map.of("requestId", requestId, "prompt", prompt));
    }

    @GetMapping("/internal/users/{username}/escalation-protection")
    public List<AnalysisEventRecorder.AnalysisEvent> escalationProtection(@PathVariable("username") String username) {
        return analysisEvents.escalationProtectionOf(username);
    }

    @GetMapping("/internal/users/{username}/embeddings")
    public List<UsageLedger.ModelCall> embeddings(@PathVariable("username") String username) {
        return usage.callsOf("user:" + username);
    }

    @GetMapping("/internal/usage/unattributed")
    public UsageLedger.Unattributed unattributedUsage() {
        return usage.unattributed();
    }

    @GetMapping("/internal/engine")
    public Map<String, Object> engine() {
        Map<String, Object> engine = new LinkedHashMap<>();
        BuildProperties properties = build.getIfAvailable();
        // Build facts D does not know are left out (null), never written as a placeholder (fabricated-data survey P1).
        engine.put("engineVersion", properties == null ? null : properties.getVersion());
        engine.put("codeCommit", properties == null ? null : properties.get("git.commit"));
        engine.put("effectiveMode", zeroTrust.isEnabled() ? zeroTrust.getMode().name() : "DISABLED");
        engine.put("chatModel", chatModel);
        engine.put("embeddingModel", embeddingModel);
        engine.put("embeddingDimensions", embeddingDimensions);
        engine.put("timeZone", ZoneId.systemDefault().getId());
        engine.put("endpointProtection", EndpointProtection.describe());
        // The model settings the engine sends with every analysis (R-20): they change the verdicts, so a run records them.
        TieredStrategyProperties tiered = tieredProperties.getIfAvailable();
        if (tiered != null) {
            engine.put("layer1Model", modelSettings(tiered.getLayer1().getOpenAiReasoningEffort(),
                    tiered.getLayer1().getOpenAiVerbosity(), tiered.getLayer1().getMaxOutputTokens()));
            engine.put("layer2Model", modelSettings(tiered.getLayer2().getOpenAiReasoningEffort(),
                    tiered.getLayer2().getOpenAiVerbosity(), tiered.getLayer2().getMaxOutputTokens()));
        }
        // True only on a development stack that accepts forced decisions; the portal refuses to record replays then.
        engine.put("forcedActions", forcedActions);
        // How long the engine keeps behaviour documents, as configured here; null when this app leaves the core's own
        // default in place (the adoption screen states a value only when it is known).
        engine.put("behaviorRetentionDays", behaviorRetentionDays);
        engine.put("actions", actions());
        return engine;
    }

    /**
     * What each decision does to the user's next requests as the engine's ZeroTrustAction defines it: the HTTP status
     * of a refused request and how long the decision stays in force (null when it stays until released). The demo's
     * follow-up screens show these values instead of writing them down.
     */
    private static Map<String, Object> actions() {
        Map<String, Object> actions = new LinkedHashMap<>();
        for (ZeroTrustAction action : List.of(ZeroTrustAction.ALLOW, ZeroTrustAction.CHALLENGE,
                ZeroTrustAction.ESCALATE, ZeroTrustAction.BLOCK)) {
            Map<String, Object> facts = new LinkedHashMap<>();
            facts.put("httpStatus", action.getHttpStatus());
            facts.put("ttlSeconds", action.getDefaultTtl() == null ? null : action.getDefaultTtl().toSeconds());
            actions.put(action.name(), facts);
        }
        return actions;
    }

    private static Map<String, Object> modelSettings(String reasoningEffort, String verbosity, int maxOutputTokens) {
        Map<String, Object> settings = new LinkedHashMap<>();
        settings.put("reasoningEffort", reasoningEffort);
        settings.put("verbosity", verbosity);
        settings.put("maxOutputTokens", maxOutputTokens);
        return settings;
    }
}
