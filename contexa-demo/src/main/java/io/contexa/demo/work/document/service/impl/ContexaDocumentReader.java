package io.contexa.demo.work.document.service.impl;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.document.dto.DocumentReadResult;
import io.contexa.demo.work.document.repository.DocumentReadRepository;
import io.contexa.demo.work.document.repository.DocumentRepository;
import io.contexa.demo.work.document.service.support.AbstractDocumentReader;
import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@Profile("contexa")
public class ContexaDocumentReader extends AbstractDocumentReader {

    public ContexaDocumentReader(DocumentRepository documents, DocumentReadRepository reads, DocumentCodec codec,
            ApprovalUsageQuery approvals) {
        super(documents, reads, codec, approvals);
    }

    @Override
    @Protectable
    public DocumentReadResult read(BusinessRequestSnapshot snapshot) {
        return readDocument(snapshot);
    }
}
