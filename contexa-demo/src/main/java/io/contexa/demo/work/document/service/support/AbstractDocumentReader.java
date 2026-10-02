package io.contexa.demo.work.document.service.support;

import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.document.dto.DocumentBody;
import io.contexa.demo.work.document.dto.DocumentReadResult;
import io.contexa.demo.work.document.repository.DocumentReadRepository;
import io.contexa.demo.work.document.repository.DocumentRepository;
import io.contexa.demo.work.document.service.DocumentReader;
import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

public abstract class AbstractDocumentReader extends AbstractDocumentOperation implements DocumentReader {

    private final DocumentReadRepository reads;

    protected AbstractDocumentReader(DocumentRepository documents, DocumentReadRepository reads, DocumentCodec codec,
            ApprovalUsageQuery approvals) {
        super(documents, codec, approvals);
        this.reads = reads;
    }

    protected DocumentReadResult readDocument(BusinessRequestSnapshot snapshot) {
        DocumentBody body = requireDocument(snapshot);
        String content = codec.write(body.content());
        DocumentReadResult result = new DocumentReadResult(snapshot.requestId(), body, codec.hash(content),
                content.getBytes(StandardCharsets.UTF_8).length, Instant.now());
        reads.append(result);
        return result;
    }
}
