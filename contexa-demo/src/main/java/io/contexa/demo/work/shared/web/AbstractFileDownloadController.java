package io.contexa.demo.work.shared.web;

import io.contexa.demo.work.participant.service.WorkParticipantQuery;
import io.contexa.demo.work.shared.dto.BusinessFile;
import org.springframework.http.CacheControl;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

public abstract class AbstractFileDownloadController extends AbstractWorkController {

    protected AbstractFileDownloadController(WorkParticipantQuery participants) {
        super(participants);
    }

    protected ResponseEntity<byte[]> file(BusinessFile file, String contentType, int preparedItems, boolean reused) {
        byte[] content = file.content();
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .contentType(MediaType.parseMediaType(contentType)).contentLength(content.length)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(file.filename()).build().toString())
                .header("X-Lab-File-Id", file.id().toString())
                .header("X-Lab-File-Sha256", file.contentSha256())
                .header("X-Lab-File-Reused", Boolean.toString(reused))
                .header("X-Lab-Prepared-Items", Integer.toString(preparedItems))
                .body(content);
    }
}
