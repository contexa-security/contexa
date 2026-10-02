package io.contexa.demo.experience.assessment.dto;

import java.time.Instant;
import java.util.UUID;

public record StoredAssessment(
        UUID id,
        UUID reportId,
        Instant createdAt,
        String inputSha256,
        AssessmentPosition position,
        UUID requestId,
        String comment
) {
}
