package io.contexa.demo.work.download.service.impl;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.document.repository.DocumentRepository;
import io.contexa.demo.work.download.dto.DocumentDownloadInput;
import io.contexa.demo.work.download.dto.DocumentDownloadResult;
import io.contexa.demo.work.download.repository.DocumentDownloadRepository;
import io.contexa.demo.work.download.service.support.AbstractDocumentDownloader;
import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@Profile("contexa")
public class ContexaDocumentDownloader extends AbstractDocumentDownloader {

    public ContexaDocumentDownloader(DocumentRepository documents, DocumentCodec codec,
            DocumentDownloadRepository downloads, ApprovalUsageQuery approvals) {
        super(documents, codec, downloads, approvals);
    }

    @Override
    @Protectable
    public DocumentDownloadResult download(BusinessRequestSnapshot snapshot, DocumentDownloadInput input) {
        return prepareFile(snapshot, input);
    }
}
