package io.contexa.showcase.workload.contexa.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.inspection.PromptInspectionReinspection;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionResultStore;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * N-SRC-3: the portal asks control D to inspect a decision's sealed package before it cleans the run up, so the source
 * checks read the run's records while they are there.
 */
class SealedPromptInspectionControllerTest {

    private final SealedEvidencePackageRepository packages = mock(SealedEvidencePackageRepository.class);
    private final PromptInspectionReinspection reinspection = mock(PromptInspectionReinspection.class);

    @Test
    void aSealedDecisionIsInspectedAtOnce() {
        SealedEvidencePackage sealed = mock(SealedEvidencePackage.class);
        when(sealed.getPackageId()).thenReturn("pkg-1");
        when(packages.findByCorrelationId("req-1")).thenReturn(Optional.of(sealed));
        when(reinspection.reinspect("pkg-1")).thenReturn(Optional.of(new PromptInspectionResult("pkg-1",
                "prompt-inspector/22", "dictionary-1", "layout-1", PromptInspectionVerdict.PASS, List.of(), null)));

        ResponseEntity<Map<String, Object>> answer = controller().inspection("req-1");

        assertThat(answer.getStatusCode().value()).isEqualTo(200);
        assertThat(answer.getBody()).containsEntry("packageId", "pkg-1")
                .containsEntry("inspectorVersion", "prompt-inspector/22").containsEntry("verdict", "PASS");
        verify(reinspection).reinspect("pkg-1");
    }

    @Test
    void aDecisionWhosePackageIsNotStoredYetIsNotFound() {
        when(packages.findByCorrelationId("req-2")).thenReturn(Optional.empty());

        assertThat(controller().inspection("req-2").getStatusCode().value()).isEqualTo(404);
        verify(reinspection, never()).reinspect(anyString());
    }

    private SealedPromptFactsController controller() {
        return new SealedPromptFactsController(provider(packages), provider(mock(PromptInspectionResultStore.class)),
                provider(reinspection), new ObjectMapper());
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> provider(T value) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(value);
        return provider;
    }
}
