package io.contexa.showcase.portal.lab;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.showcase.portal.anatomy.SealedPrompts;
import io.contexa.showcase.portal.reactivity.ReactivityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * W7-13: the lab result's "what changed in the model's input" (lab-3, docs/showcase/화면설계-프롬프트신뢰-보강안.md 3.4,
 * 5), compared on the server against the designed run of the same case. The comparison reads the sealed prompts
 * through control D, so it answers only where the portal has control D; a run that is not a lab run is not found.
 */
@RestController
public class LabDeltaController {

    private static final Logger log = LoggerFactory.getLogger(LabDeltaController.class);

    private final LabStore lab;
    private final ObjectProvider<ReactivityService> reactivity;
    private final ObjectProvider<SealedPrompts> prompts;

    public LabDeltaController(LabStore lab, ObjectProvider<ReactivityService> reactivity,
                              ObjectProvider<SealedPrompts> prompts) {
        this.lab = lab;
        this.reactivity = reactivity;
        this.prompts = prompts;
    }

    @GetMapping("/api/lab/runs/{runId}/delta")
    public ResponseEntity<LabDelta> delta(@PathVariable("runId") String runId) {
        ReactivityService service = reactivity.getIfAvailable();
        SealedPrompts sealed = prompts.getIfAvailable();
        if (service == null || sealed == null || !LabController.RUN_ID.matcher(runId).matches()) {
            return ResponseEntity.notFound().build();
        }
        Optional<LabStore.Composition> composition = lab.composition(runId);
        if (composition.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        LabStore.Composition run = composition.get();
        String refused = LabDelta.refusal(run);
        if (refused != null) {
            return ResponseEntity.ok(LabDelta.without(run, null, refused));
        }
        Optional<String> base = lab.designedBase(run);
        if (base.isEmpty()) {
            return ResponseEntity.ok(LabDelta.without(run, null, LabDelta.NO_BASE));
        }
        try {
            ReactivityService.RunDelivery delivery = service.delivery(base.get(), runId, LabDelta.condition(run),
                    LabDelta.value(run));
            Map<String, JsonNode> facts = new HashMap<>();
            for (ReactivityService.StepDelivery step : delivery.steps()) {
                if (step.delivery() != null) {
                    facts.put(step.baseRequestId(), sealed.facts(step.baseRequestId()).orElse(null));
                    facts.put(step.variantRequestId(), sealed.facts(step.variantRequestId()).orElse(null));
                }
            }
            return ResponseEntity.ok(LabDelta.of(run, delivery, facts));
        } catch (IOException e) {
            log.error("Lab delta unreadable from control D: runId={}, baseRunId={}", runId, base.get(), e);
            return ResponseEntity.ok(LabDelta.without(run, base.get(), LabDelta.NO_ENGINE));
        }
    }
}
