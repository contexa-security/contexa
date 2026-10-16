package io.contexa.showcase.workload.contexa.internal;

import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceEmpiricalEvalService;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceRegistryService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * W8-3 (P8, W6-8 design: the showcase harness records the evaluation after a measurement): the harness's evaluation
 * of a bundle on control D (internal API, guarded like every {@code /internal/**} path), through the OSS empirical
 * evaluation service with the bundle hash and the runs it counted, so the release gate takes it as that bundle's
 * evidence only. Gate values the measurement did not cover are sent as NOT_VERIFIED by the harness.
 */
@RestController
public class PromptEvaluationHarnessController {

    private final ObjectProvider<PromptGovernanceEmpiricalEvalService> evaluations;

    public PromptEvaluationHarnessController(ObjectProvider<PromptGovernanceEmpiricalEvalService> evaluations) {
        this.evaluations = evaluations;
    }

    /** What the harness measured for a bundle version: the gate states, the families covered, hash and runs. */
    public record EvaluationRequest(String promptVersion, String evaluationReference, String evaluationMode,
                                    List<String> coveredScenarioFamilies, String promptInjectionState,
                                    String latencyGateState, String costGateState, String summary, String bundleHash,
                                    String runReference) {
    }

    @PostMapping("/internal/prompt-releases/evaluation")
    public ResponseEntity<PromptGovernanceEmpiricalEvalService.EvalRegistrationReceipt> record(
            @RequestBody EvaluationRequest request) {
        PromptGovernanceEmpiricalEvalService service = evaluations.getIfAvailable();
        if (service == null) {
            return ResponseEntity.notFound().build();
        }
        if (request.bundleHash() == null || request.bundleHash().isBlank() || request.runReference() == null
                || request.runReference().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        try {
            return ResponseEntity.ok(service.recordEvaluation(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                    PromptReleaseHarnessController.PROMPT_KEY, request.promptVersion(), request.evaluationReference(),
                    request.evaluationMode(), request.coveredScenarioFamilies(), request.promptInjectionState(),
                    request.latencyGateState(), request.costGateState(), PromptReleaseHarnessController.ACTOR,
                    request.summary(), request.bundleHash(), request.runReference()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
    }
}
