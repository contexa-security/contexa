package io.contexa.demo.comparison.preparation.source.impl;

import io.contexa.demo.comparison.preparation.dto.ArmDocumentFingerprint;
import io.contexa.demo.comparison.preparation.source.ComparisonDocumentSource;
import io.contexa.demo.comparison.preparation.source.support.AbstractStoredComparisonSource;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.document.dto.DocumentBody;
import io.contexa.demo.work.document.dto.DocumentSummary;
import io.contexa.demo.work.document.repository.DocumentRepository;

public class StoredComparisonDocumentSource extends AbstractStoredComparisonSource<ArmDocumentFingerprint>
        implements ComparisonDocumentSource {

    private final DocumentRepository repository;

    public StoredComparisonDocumentSource(String arm, DocumentRepository repository, DocumentCodec documents) {
        super(arm, documents);
        this.repository = repository;
    }

    @Override
    protected ArmDocumentFingerprint read(String documentId) {
        DocumentSummary summary = repository.find(documentId);
        DocumentBody body = summary == null ? null : repository.read(documentId, summary.version());
        return body == null ? null : new ArmDocumentFingerprint(arm, "CAPTURED", documentId,
                summary.version(), summary.projectId(), documents.hash(documents.write(body)),
                documents.hash(documents.write(body.content())), summary.title());
    }

    @Override
    protected ArmDocumentFingerprint missing(String documentId, String state) {
        return new ArmDocumentFingerprint(arm, state, documentId, null, null, null, null, null);
    }
}
