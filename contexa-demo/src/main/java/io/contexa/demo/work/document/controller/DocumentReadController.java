package io.contexa.demo.work.document.controller;

import io.contexa.demo.work.document.dto.DocumentReadResult;
import io.contexa.demo.work.document.service.DocumentReader;
import io.contexa.demo.work.participant.service.WorkParticipantQuery;
import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;
import io.contexa.demo.work.request.dto.DocumentReadInput;
import io.contexa.demo.work.request.service.BusinessRequestPreparation;
import io.contexa.demo.work.request.web.BusinessContextAttributes;
import io.contexa.demo.work.shared.web.AbstractWorkController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Profile({"baseline", "contexa"})
@RequestMapping("/api/work/documents")
public class DocumentReadController extends AbstractWorkController {

    private final BusinessRequestPreparation preparation;
    private final DocumentReader reader;

    public DocumentReadController(WorkParticipantQuery participants, BusinessRequestPreparation preparation,
            DocumentReader reader) {
        super(participants);
        this.preparation = preparation;
        this.reader = reader;
    }

    @PostMapping("/{id}/read")
    public ResponseEntity<DocumentReadResult> read(@PathVariable String id, @Valid @RequestBody DocumentReadInput input,
            HttpServletRequest request, Authentication authentication) {
        BusinessRequestSnapshot snapshot = preparation.prepare(BusinessContextAttributes.requestId(request),
                participant(request, authentication), id, input.purpose(), input.approvalId());
        BusinessContextAttributes.attach(request, snapshot);
        return result(reader.read(snapshot));
    }
}
