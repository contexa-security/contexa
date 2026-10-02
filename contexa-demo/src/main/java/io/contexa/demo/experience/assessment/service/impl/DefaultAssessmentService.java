package io.contexa.demo.experience.assessment.service.impl;

import io.contexa.demo.experience.assessment.dto.AssessmentCommand;
import io.contexa.demo.experience.assessment.dto.StoredAssessment;
import io.contexa.demo.experience.assessment.repository.AssessmentRepository;
import io.contexa.demo.experience.assessment.service.AssessmentService;
import io.contexa.demo.experience.report.service.ReportService;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@Profile("portal")
public class DefaultAssessmentService implements AssessmentService {

    private final ReportService reports;
    private final AssessmentRepository assessments;
    private final DocumentCodec documents;

    public DefaultAssessmentService(ReportService reports, AssessmentRepository assessments, DocumentCodec documents) {
        this.reports = reports;
        this.assessments = assessments;
        this.documents = documents;
    }

    @Override
    public StoredAssessment submit(UUID visitorId, UUID reportId, AssessmentCommand command) {
        var report = reports.find(visitorId, reportId);
        if (command.requestId() != null && report.payload().sources().stream()
                .noneMatch(source -> command.requestId().equals(source.requestId()))) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "REQUEST_NOT_IN_REPORT");
        }
        String hash = documents.hash(documents.write(command));
        StoredAssessment previous = assessments.findCommand(visitorId, command.commandId());
        if (previous != null) {
            return matching(previous, reportId, hash);
        }
        var candidate = new StoredAssessment(UUID.randomUUID(), reportId, Instant.now(), hash,
                command.position(), command.requestId(), command.comment());
        return matching(assessments.save(visitorId, command.commandId(), candidate), reportId, hash);
    }

    @Override
    public List<StoredAssessment> list(UUID visitorId, UUID reportId) {
        reports.find(visitorId, reportId);
        return assessments.list(visitorId, reportId);
    }

    private StoredAssessment matching(StoredAssessment value, UUID reportId, String hash) {
        if (!reportId.equals(value.reportId()) || !hash.equals(value.inputSha256())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "ASSESSMENT_COMMAND_ALREADY_USED");
        }
        return value;
    }
}
