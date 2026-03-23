package io.contexa.contexacore.autonomous.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LearningMetadataTest {

    @Test
    void canLearnDoesNotDependOnAuditConfidenceScore() {
        LearningMetadata metadata = LearningMetadata.builder()
                .isLearnable(true)
                .confidenceScore(0.12)
                .status(LearningMetadata.LearningStatus.PENDING)
                .build();

        assertThat(metadata.canLearn()).isTrue();
    }
}
