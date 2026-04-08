package io.contexa.contexacore.autonomous.saas.learning.prompt;

import io.contexa.contexacore.autonomous.saas.dto.PromptPresentationPackSnapshot;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PromptPresentationPackAssemblerTest {

    private final PromptBiasRiskEvaluator biasRiskEvaluator = new DefaultPromptBiasRiskEvaluator();
    private final PromptPresentationPackAssembler assembler = new PromptPresentationPackAssembler();

    @Test
    void assemblesOnlyPromotablePromptPresentationPatterns() {
        PromptPresentationExperimentResult promotableResult = new PromptPresentationExperimentResult(
                new PromptPresentationPatternProfile(
                        "pattern-low",
                        "security-decision",
                        "standard",
                        "v1",
                        "STRUCTURED",
                        false,
                        "COMPLETE",
                        List.of("summary", "evidence", "policy"),
                        List.of()),
                12L,
                6L,
                0L,
                0L,
                0L,
                1L,
                12L,
                0.2d,
                0.0d,
                0.48d,
                List.of("evidence fact"),
                List.of("policy fact"));
        PromptPresentationExperimentResult blockedResult = new PromptPresentationExperimentResult(
                new PromptPresentationPatternProfile(
                        "pattern-high",
                        "security-decision",
                        "compact",
                        "v1",
                        "CONDENSED",
                        true,
                        "PARTIAL",
                        List.of("summary", "evidence"),
                        List.of("narrative")),
                10L,
                6L,
                5L,
                1L,
                4L,
                8L,
                10L,
                2.6d,
                1.8d,
                0.94d,
                List.of("evidence fact"),
                List.of("policy fact"));

        PromptPresentationPackSnapshot snapshot = assembler.assembleSnapshot(
                "tenant-a",
                true,
                true,
                List.of(
                        PromptPresentationPackCandidate.from(promotableResult, biasRiskEvaluator.evaluate(promotableResult)),
                        PromptPresentationPackCandidate.from(blockedResult, biasRiskEvaluator.evaluate(blockedResult))));

        assertThat(snapshot.tenantId()).isEqualTo("tenant-a");
        assertThat(snapshot.featureEnabled()).isTrue();
        assertThat(snapshot.sharingEnabled()).isTrue();
        assertThat(snapshot.runtimeReady()).isFalse();
        assertThat(snapshot.promotionState()).isEqualTo("SHADOW_READY");
        assertThat(snapshot.promotedPatternCount()).isZero();
        assertThat(snapshot.candidatePatternCount()).isEqualTo(1L);
        assertThat(snapshot.blockedPatternCount()).isEqualTo(1L);
        assertThat(snapshot.patterns()).hasSize(1);
        assertThat(snapshot.patterns().get(0).presentationPatternKey()).isEqualTo("pattern-low");
        assertThat(snapshot.patterns().get(0).biasRiskState()).isEqualTo("LOW");
        assertThat(snapshot.patterns().get(0).supportedPromptFamilies()).containsExactly("security-decision", "standard");
        assertThat(snapshot.patterns().get(0).supportedModelFamilies()).isEmpty();
        assertThat(snapshot.patterns().get(0).supportedContextCoverageBand()).isEqualTo("STRONG");
    }

    @Test
    void reportsReviewOnlyStateWhenAllPatternsAreBlocked() {
        PromptPresentationExperimentResult blockedResult = new PromptPresentationExperimentResult(
                new PromptPresentationPatternProfile(
                        "pattern-high",
                        "security-decision",
                        "compact",
                        "v1",
                        "CONDENSED",
                        true,
                        "PARTIAL",
                        List.of("summary", "evidence"),
                        List.of("narrative")),
                10L,
                6L,
                5L,
                1L,
                4L,
                8L,
                10L,
                2.6d,
                1.8d,
                0.94d,
                List.of("evidence fact"),
                List.of("policy fact"));

        PromptPresentationPackSnapshot snapshot = assembler.assembleSnapshot(
                "tenant-a",
                true,
                true,
                List.of(PromptPresentationPackCandidate.from(blockedResult, biasRiskEvaluator.evaluate(blockedResult))));

        assertThat(snapshot.promotionState()).isEqualTo("REVIEW_ONLY");
        assertThat(snapshot.candidatePatternCount()).isZero();
        assertThat(snapshot.blockedPatternCount()).isEqualTo(1L);
        assertThat(snapshot.patterns()).isEmpty();
    }
}