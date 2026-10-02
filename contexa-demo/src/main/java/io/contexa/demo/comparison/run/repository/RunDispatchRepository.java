package io.contexa.demo.comparison.run.repository;

import io.contexa.demo.comparison.run.dto.DispatchClaim;
import java.util.UUID;

public interface RunDispatchRepository {

    DispatchClaim claim(UUID visitorId, UUID runId, UUID stepId, String arm, UUID requestId);

    void reject(UUID visitorId, UUID runId, UUID stepId, String arm, String reason);

    void respond(UUID runId, UUID stepId, UUID requestId, Integer httpStatus, String failureType);
}
