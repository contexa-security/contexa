package io.contexa.demo.work.download.controller;

import io.contexa.demo.work.download.dto.DocumentDownloadInput;
import io.contexa.demo.work.download.dto.DocumentDownloadResult;
import io.contexa.demo.work.download.service.DocumentDownloader;
import io.contexa.demo.work.participant.service.WorkParticipantQuery;
import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;
import io.contexa.demo.work.request.dto.DocumentOperation;
import io.contexa.demo.work.request.service.BusinessRequestPreparation;
import io.contexa.demo.work.request.web.BusinessContextAttributes;
import io.contexa.demo.work.shared.web.AbstractFileDownloadController;
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
public class DocumentDownloadController extends AbstractFileDownloadController {

    private final BusinessRequestPreparation preparation;
    private final DocumentDownloader downloader;

    public DocumentDownloadController(WorkParticipantQuery participants, BusinessRequestPreparation preparation,
            DocumentDownloader downloader) {
        super(participants);
        this.preparation = preparation;
        this.downloader = downloader;
    }

    @PostMapping("/{id}/download")
    public ResponseEntity<byte[]> download(@PathVariable String id, @Valid @RequestBody DocumentDownloadInput input,
            HttpServletRequest request, Authentication authentication) {
        BusinessRequestSnapshot snapshot = preparation.prepare(BusinessContextAttributes.requestId(request),
                participant(request, authentication), id, input.purpose(), DocumentOperation.DOWNLOAD, input.approvalId());
        BusinessContextAttributes.attach(request, snapshot);
        DocumentDownloadResult result = downloader.download(snapshot, input);
        return file(result.file(), "text/plain;charset=UTF-8", 1, result.reused());
    }
}
