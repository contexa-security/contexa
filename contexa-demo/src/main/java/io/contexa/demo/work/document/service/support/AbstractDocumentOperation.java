package io.contexa.demo.work.document.service.support;

import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.document.dto.DocumentBody;
import io.contexa.demo.work.document.repository.DocumentRepository;
import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;
import io.contexa.demo.work.shared.service.support.AbstractBusinessOperation;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public abstract class AbstractDocumentOperation extends AbstractBusinessOperation {

    private final DocumentRepository documents;
    protected final DocumentCodec codec;

    protected AbstractDocumentOperation(DocumentRepository documents, DocumentCodec codec, ApprovalUsageQuery approvals) {
        super(approvals);
        this.documents = documents;
        this.codec = codec;
    }

    protected DocumentBody requireDocument(BusinessRequestSnapshot snapshot) {
        requireApproval(snapshot);
        DocumentBody body = documents.read(snapshot.document().id(), snapshot.document().version());
        if (body == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return body;
    }
}
