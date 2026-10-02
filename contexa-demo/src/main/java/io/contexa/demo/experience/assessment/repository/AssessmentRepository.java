package io.contexa.demo.experience.assessment.repository;

import io.contexa.demo.experience.assessment.dto.StoredAssessment;
import java.util.List;
import java.util.UUID;

public interface AssessmentRepository {

    StoredAssessment findCommand(UUID visitorId, UUID commandId);

    StoredAssessment save(UUID visitorId, UUID commandId, StoredAssessment value);

    List<StoredAssessment> list(UUID visitorId, UUID reportId);
}
