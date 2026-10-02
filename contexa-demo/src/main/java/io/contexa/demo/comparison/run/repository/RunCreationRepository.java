package io.contexa.demo.comparison.run.repository;

import io.contexa.demo.comparison.run.dto.RunRecord;
import java.util.UUID;

public interface RunCreationRepository {

    RunRecord save(RunRecord candidate);

    RunRecord reuse(UUID visitorId, UUID commandId, String submittedInputSha256);
}
