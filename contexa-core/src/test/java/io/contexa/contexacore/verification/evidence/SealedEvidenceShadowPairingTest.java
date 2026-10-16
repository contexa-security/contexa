package io.contexa.contexacore.verification.evidence;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.processor.PromptShadowRunner;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceResolutionContext;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelection;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.bundle.PromptShadowRun;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * N-SHD-1: a shadow run's seal names the request its copy was made from, under the id the decision is sealed with,
 * so the shadow's answer is paired with the decision's answer request by request. The copy is still traced and sealed
 * under its own request id, apart from the decision (no shared trace key, correlation id or idempotency key).
 */
class SealedEvidenceShadowPairingTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    private final SealedEvidencePromptTraceStore traceStore = new SealedEvidencePromptTraceStore();
    private final SealedEvidencePackageAssembler assembler = new SealedEvidencePackageAssembler(
            JSON, new CanonicalSecurityContextSerializer(JSON), new SealedEvidencePackageIntegrity(), traceStore);
    private final SealedEvidencePackageRepository repository = mock(SealedEvidencePackageRepository.class);

    @Test
    void theShadowSealNamesTheRequestItsDecisionIsSealedUnder() throws Exception {
        SecurityEvent original = event("evt-1");
        original.addMetadata("requestId", "req-1");
        original.addMetadata("correlationId", "req-1");
        original.addMetadata(SecurityPlaneAgent.EVENT_PROCESSING_IDENTITY, "identity-1");

        Sealed pair = sealBoth(original);

        assertThat(pair.decision().getCorrelationId()).isEqualTo("req-1");
        assertThat(pair.decision().getIdempotencyKey()).isEqualTo("identity-1");
        assertThat(pair.shadow().getCorrelationId()).startsWith("shadow-").isNotEqualTo("req-1");
        assertThat(pair.shadow().getIdempotencyKey()).isNull();
        assertThat(pair.shadow().getUserPromptText()).isEqualTo("shadow prompt");
        assertThat(pair.decision().getUserPromptText()).isEqualTo("decision prompt");
        Map<String, Object> shadowDecision = JSON.readValue(pair.shadow().getDecisionJson(), MAP);
        assertThat(shadowDecision).containsEntry("decisionAppliedStage", "SHADOW")
                .containsEntry(PromptShadowRun.ORIGINAL_REQUEST_ID, pair.decision().getCorrelationId())
                .containsEntry("action", "ALLOW");
        assertThat(JSON.readValue(pair.decision().getDecisionJson(), MAP))
                .doesNotContainKey(PromptShadowRun.ORIGINAL_REQUEST_ID);
        assertThat(new SealedEvidencePackageIntegrity().evaluate(pair.shadow()))
                .isEqualTo(SealedEvidencePackageIntegrity.Status.VERIFIED);
    }

    @Test
    void withoutARequestIdTheShadowSealNamesTheCorrelationOrTheEventItsDecisionIsSealedUnder() throws Exception {
        SecurityEvent byCorrelation = event("evt-2");
        byCorrelation.addMetadata("correlationId", "corr-2");
        SecurityEvent byEvent = event("evt-3");

        for (SecurityEvent original : List.of(byCorrelation, byEvent)) {
            Sealed pair = sealBoth(original);

            assertThat(JSON.readValue(pair.shadow().getDecisionJson(), MAP))
                    .containsEntry(PromptShadowRun.ORIGINAL_REQUEST_ID, pair.decision().getCorrelationId());
        }
    }

    private record Sealed(SealedEvidencePackage decision, SealedEvidencePackage shadow) {
    }

    /** The decision and its shadow run, each traced and sealed the way the cold path does. */
    private Sealed sealBoth(SecurityEvent original) {
        PromptShadowRunner runner = runner();
        SecurityEvent copy = runner.prepare(original);
        assertThat(copy).isNotNull();

        trace(original, "decision prompt");
        SealedEvidencePackage decision = assembler.assemble(context(original, "BLOCK"));
        assertThat(decision).isNotNull();

        trace(copy, "shadow prompt");
        runner.run(copy, analysed -> result("ALLOW"));
        ArgumentCaptor<SealedEvidencePackage> saved = ArgumentCaptor.forClass(SealedEvidencePackage.class);
        verify(repository, atLeastOnce()).save(saved.capture());
        return new Sealed(decision, saved.getValue());
    }

    private PromptShadowRunner runner() {
        PromptBundleSelector selector = new PromptBundleSelector() {
            @Override
            public PromptBundleSelection select(PromptGovernanceResolutionContext context, String subjectKey) {
                return PromptBundleSelection.none();
            }

            @Override
            public PromptBundleSelection shadow(PromptGovernanceResolutionContext context, String subjectKey) {
                return new PromptBundleSelection(SecurityDecisionPromptBundles.DEFAULT.version(),
                        PromptBundleSelectionSource.SHADOW);
            }
        };
        return new PromptShadowRunner(selector, event -> new PromptGovernanceResolutionContext("PLATFORM_GLOBAL",
                "cortex.security-decision", "SecurityDecisionStandard", null, null, null, null, Map.of()),
                Runnable::run, new SealedEvidenceShadowSealer(assembler, repository), 100, 10,
                Clock.fixed(Instant.parse("2026-10-16T01:00:00Z"), ZoneOffset.UTC));
    }

    private void trace(SecurityEvent event, String userPrompt) {
        PromptGenerationResult prompt = mock(PromptGenerationResult.class);
        when(prompt.getSystemPrompt()).thenReturn("system prompt");
        when(prompt.getUserPrompt()).thenReturn(userPrompt);
        when(prompt.getRawSystemPrompt()).thenReturn("system prompt");
        when(prompt.getRawUserPrompt()).thenReturn(userPrompt);
        when(prompt.getMetadata()).thenReturn(Map.of());
        SecurityDecisionContext capture = mock(SecurityDecisionContext.class);
        when(capture.getSecurityEvent()).thenReturn(event);
        when(capture.getRelatedDocuments()).thenReturn(List.of());
        traceStore.capture(capture, prompt);
        traceStore.complete(event);
    }

    private static SecurityEventContext context(SecurityEvent event, String action) {
        SecurityEventContext context = new SecurityEventContext(event);
        context.addMetadata("processingResult", result(action));
        return context;
    }

    private static ProcessingResult result(String action) {
        ProcessingResult result = ProcessingResult.builder().success(true).build();
        result.setAction(action);
        return result;
    }

    private static SecurityEvent event(String eventId) {
        SecurityEvent event = SecurityEvent.builder().eventId(eventId).userId("alice").sessionId("s-1").build();
        event.addMetadata("requestPath", "/api/projects/PLM-OPS/exports");
        return event;
    }
}
