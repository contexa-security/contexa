package io.contexa.demo.comparison.preparation.repository;

import io.contexa.demo.comparison.preparation.dto.PreparedComparison;

import java.util.UUID;

public interface ComparisonPreparationRepository {

    PreparedComparison find(UUID visitorId, UUID id);

    PreparedComparison findCommand(UUID visitorId, UUID commandId);

    PreparedComparison save(PreparedComparison candidate, String submittedInputSha256, UUID workspaceId);
}
