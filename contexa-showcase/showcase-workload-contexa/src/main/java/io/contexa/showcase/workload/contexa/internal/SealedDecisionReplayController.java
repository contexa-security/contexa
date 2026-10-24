package io.contexa.showcase.workload.contexa.internal;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.BaselineLearningService;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.llm.client.StructuredOutputCapabilityRegistry;
import io.contexa.contexacore.std.llm.strategy.ModelSelectionStrategy;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * The replay of a sealed decision with a chosen bundle for the measurement harness (V-2.2 of the v21 plan, internal
 * API, guarded like every {@code /internal/**} path): the decision's sealed inputs and the baselines of the template its
 * run cloned, drawn through the engine's template, pipeline and first-layer options, asked once. The answer is returned
 * and nothing is applied, learned or sealed; the model call is recorded under the replay's own request id.
 * <p>
 * Retired by docs/agent OC-5 (Contexa's replay admin API replaces it) and no longer registered; the file waits for
 * deletion.
 */
public class SealedDecisionReplayController {

    /** The longest a replay waits: a call and its one retry, each within the first layer's call limit. */
    private static final Duration REPLAY_TIMEOUT = Duration.ofMinutes(3);

    private final ObjectProvider<SealedEvidencePackageRepository> packages;
    private final ObjectProvider<SecurityDecisionStandardPromptTemplate> templates;
    private final ObjectProvider<PipelineOrchestrator> pipelines;
    private final ObjectProvider<BaselineLearningService> baselines;
    private final ObjectProvider<TieredStrategyProperties> tiered;
    private final ObjectProvider<SecurityZeroTrustProperties> zeroTrust;
    private final ObjectProvider<StructuredOutputCapabilityRegistry> structuredOutput;
    private final ObjectProvider<ModelSelectionStrategy> modelSelection;
    private final ObjectProvider<CanonicalSecurityContextSerializer> serializers;
    private final ObjectMapper objectMapper;

    public SealedDecisionReplayController(ObjectProvider<SealedEvidencePackageRepository> packages,
                                          ObjectProvider<SecurityDecisionStandardPromptTemplate> templates,
                                          ObjectProvider<PipelineOrchestrator> pipelines,
                                          ObjectProvider<BaselineLearningService> baselines,
                                          ObjectProvider<TieredStrategyProperties> tiered,
                                          ObjectProvider<SecurityZeroTrustProperties> zeroTrust,
                                          ObjectProvider<StructuredOutputCapabilityRegistry> structuredOutput,
                                          ObjectProvider<ModelSelectionStrategy> modelSelection,
                                          ObjectProvider<CanonicalSecurityContextSerializer> serializers,
                                          ObjectMapper objectMapper) {
        this.packages = packages;
        this.templates = templates;
        this.pipelines = pipelines;
        this.baselines = baselines;
        this.tiered = tiered;
        this.zeroTrust = zeroTrust;
        this.structuredOutput = structuredOutput;
        this.modelSelection = modelSelection;
        this.serializers = serializers;
        this.objectMapper = objectMapper.copy().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    /**
     * What to replay with: the bundle version and the baselines of the template the decision's run cloned, as the
     * template snapshot stores them (JSON texts), and the models to ask the second pass with when the replay answers
     * ESCALATE (판정층 7절; none asks no second pass).
     */
    public record ReplayRequest(String bundleVersion, String userBaseline, String organizationBaseline,
                                List<String> secondPassModels) {
    }

    @PostMapping("/internal/decisions/{requestId}/replay")
    public ResponseEntity<SealedDecisionReplayService.Result> replay(@PathVariable("requestId") String requestId,
                                                                     @RequestBody ReplayRequest request) {
        SealedEvidencePackageRepository repository = packages.getIfAvailable();
        Optional<SealedEvidencePackage> sealed = repository != null ? repository.findByCorrelationId(requestId)
                : Optional.empty();
        SecurityDecisionStandardPromptTemplate template = templates.getIfAvailable();
        PipelineOrchestrator pipeline = pipelines.getIfAvailable();
        BaselineLearningService baseline = baselines.getIfAvailable();
        if (sealed.isEmpty() || template == null || pipeline == null || baseline == null) {
            return ResponseEntity.notFound().build();
        }
        if (request == null || request.bundleVersion() == null || request.bundleVersion().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        SecurityZeroTrustProperties zeroTrustProperties = zeroTrust.getIfAvailable(SecurityZeroTrustProperties::new);
        CanonicalSecurityContextSerializer serializer =
                serializers.getIfAvailable(() -> new CanonicalSecurityContextSerializer(objectMapper));
        SealedDecisionReplayService service = new SealedDecisionReplayService(template, pipeline, baseline,
                tiered.getIfAvailable(TieredStrategyProperties::new),
                structuredOutput.getIfAvailable(StructuredOutputCapabilityRegistry::defaultRegistry),
                modelSelection::getIfAvailable,
                zeroTrustProperties.getMinimumAction().toRules(),
                zeroTrustProperties.getMinimumAction().getMode().name(),
                serializer, objectMapper);
        try {
            BaselineVector user = vector(request.userBaseline());
            if (user != null && sealed.get().getUserId() != null) {
                // As a run's clone carries it (TemplateSnapshots.importInto).
                user.setUserId(sealed.get().getUserId());
            }
            return ResponseEntity.ok(service.replay(sealed.get(), user, vector(request.organizationBaseline()),
                    request.bundleVersion().trim(), REPLAY_TIMEOUT,
                    request.secondPassModels() != null ? request.secondPassModels() : List.of()));
        }
        catch (IllegalArgumentException | IOException exception) {
            return ResponseEntity.badRequest().build();
        }
    }

    private BaselineVector vector(String json) throws IOException {
        return json == null || json.isBlank() ? null : objectMapper.readValue(json, BaselineVector.class);
    }
}
