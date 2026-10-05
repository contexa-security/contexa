package io.contexa.showcase.workload.contexa.internal;

import io.contexa.contexacore.autonomous.service.UserEngineStatePurgeResult;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.showcase.workload.contexa.inbox.DemoInboxEmailService;
import io.contexa.showcase.workload.contexa.observation.AnalysisEventRecorder;
import io.contexa.showcase.workload.contexa.observation.DecisionRecords;
import io.contexa.showcase.workload.contexa.observation.UsageLedger;
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
import java.util.List;
import java.util.Map;

/**
 * Management API of control D, called only by the portal orchestrator with a signed internal context
 * (docs/showcase/ADR.md ADR-24): run principals with their template state, template snapshots, the demo inbox, the
 * evidence of one decision, and the engine configuration that goes into the execution specification.
 */
@RestController
public class ContexaInternalController {

    public record PrincipalRequest(String username, String password, String employeeKey, String roleKey,
                                   String displayName, String department, String organizationId, String tenantId,
                                   TemplateSnapshot template) {
    }

    public record SnapshotRequest(String username, String employeeKey, String organizationId, String tenantId) {
    }

    public record DecisionEvidence(String requestId, List<DecisionRecords.DecisionRecord> records,
                                   List<AnalysisEventRecorder.AnalysisEvent> events,
                                   List<UsageLedger.ModelCall> modelCalls) {
    }

    private final RunPrincipalService principals;
    private final SharedAccountGuard sharedAccounts;
    private final OrphanPrincipalSweeper orphans;
    private final TemplateSnapshots templates;
    private final DemoInboxEmailService inbox;
    private final DecisionRecords decisions;
    private final AnalysisEventRecorder analysisEvents;
    private final UsageLedger usage;
    private final SecurityZeroTrustProperties zeroTrust;
    private final String chatModel;
    private final String embeddingModel;
    private final int embeddingDimensions;
    private final ObjectProvider<BuildProperties> build;
    private final boolean forcedActions;

    public ContexaInternalController(RunPrincipalService principals, SharedAccountGuard sharedAccounts,
                                     OrphanPrincipalSweeper orphans,
                                     TemplateSnapshots templates,
                                     DemoInboxEmailService inbox, DecisionRecords decisions,
                                     AnalysisEventRecorder analysisEvents, UsageLedger usage,
                                     SecurityZeroTrustProperties zeroTrust,
                                     @Value("${spring.ai.openai.chat.options.model:}") String chatModel,
                                     @Value("${spring.ai.openai.embedding.options.model:}") String embeddingModel,
                                     @Value("${spring.ai.openai.embedding.options.dimensions:0}") int embeddingDimensions,
                                     ObjectProvider<BuildProperties> build,
                                     @Value("${showcase.dev.forced-actions:false}") boolean forcedActions) {
        this.principals = principals;
        this.sharedAccounts = sharedAccounts;
        this.orphans = orphans;
        this.templates = templates;
        this.inbox = inbox;
        this.decisions = decisions;
        this.analysisEvents = analysisEvents;
        this.usage = usage;
        this.zeroTrust = zeroTrust;
        this.chatModel = chatModel;
        this.embeddingModel = embeddingModel;
        this.embeddingDimensions = embeddingDimensions;
        this.build = build;
        this.forcedActions = forcedActions;
    }

    @PostMapping("/internal/runs/{runId}/principals")
    public Map<String, Object> createPrincipal(@PathVariable("runId") String runId,
                                               @RequestBody PrincipalRequest request) {
        principals.create(new RunPrincipalService.Principal(request.username(), runId, request.employeeKey(),
                request.roleKey(), request.displayName(), request.department(), request.organizationId(),
                request.tenantId()), request.password());
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
                usage.callsOf(requestId));
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
        engine.put("engineVersion", properties == null ? "unknown" : properties.getVersion());
        engine.put("codeCommit", properties == null || properties.get("git.commit") == null ? "unknown"
                : properties.get("git.commit"));
        engine.put("effectiveMode", zeroTrust.isEnabled() ? zeroTrust.getMode().name() : "DISABLED");
        engine.put("chatModel", chatModel);
        engine.put("embeddingModel", embeddingModel);
        engine.put("embeddingDimensions", embeddingDimensions);
        engine.put("timeZone", ZoneId.systemDefault().getId());
        engine.put("endpointProtection", EndpointProtection.describe());
        // True only on a development stack that accepts forced decisions; the portal refuses to record replays then.
        engine.put("forcedActions", forcedActions);
        return engine;
    }
}
