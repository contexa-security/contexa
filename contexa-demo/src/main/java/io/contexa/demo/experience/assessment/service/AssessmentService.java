package io.contexa.demo.experience.assessment.service;

import io.contexa.demo.experience.assessment.dto.AssessmentCommand;
import io.contexa.demo.experience.assessment.dto.StoredAssessment;
import java.util.List;
import java.util.UUID;

public interface AssessmentService {

    StoredAssessment submit(UUID visitorId, UUID reportId, AssessmentCommand command);

    List<StoredAssessment> list(UUID visitorId, UUID reportId);
}
