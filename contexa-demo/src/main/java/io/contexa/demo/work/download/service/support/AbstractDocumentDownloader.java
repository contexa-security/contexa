package io.contexa.demo.work.download.service.support;

import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.document.repository.DocumentRepository;
import io.contexa.demo.work.document.service.support.AbstractDocumentOperation;
import io.contexa.demo.work.download.dto.DocumentDownloadInput;
import io.contexa.demo.work.download.dto.DocumentDownloadResult;
import io.contexa.demo.work.download.dto.DocumentLanguage;
import io.contexa.demo.work.download.repository.DocumentDownloadRepository;
import io.contexa.demo.work.download.service.DocumentDownloader;
import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;

public abstract class AbstractDocumentDownloader extends AbstractDocumentOperation implements DocumentDownloader {

    private final DocumentDownloadRepository downloads;

    protected AbstractDocumentDownloader(DocumentRepository documents, DocumentCodec codec,
            DocumentDownloadRepository downloads, ApprovalUsageQuery approvals) {
        super(documents, codec, approvals);
        this.downloads = downloads;
    }

    protected DocumentDownloadResult prepareFile(BusinessRequestSnapshot snapshot, DocumentDownloadInput input) {
        var body = requireDocument(snapshot);
        String content = input.language() == DocumentLanguage.KO ? body.content().ko() : body.content().en();
        return downloads.saveOrReuse(snapshot, input, content);
    }
}
