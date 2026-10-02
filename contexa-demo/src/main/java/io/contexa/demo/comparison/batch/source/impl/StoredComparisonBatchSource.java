package io.contexa.demo.comparison.batch.source.impl;

import io.contexa.demo.comparison.batch.dto.ArmBatchFingerprint;
import io.contexa.demo.comparison.batch.dto.BatchFingerprintItem;
import io.contexa.demo.comparison.batch.dto.ComparisonExportSelection;
import io.contexa.demo.comparison.batch.source.ComparisonBatchSource;
import io.contexa.demo.comparison.preparation.source.ComparisonCustomerSource;
import io.contexa.demo.comparison.preparation.source.ComparisonDocumentSource;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.export.dto.ExportResourceType;
import org.springframework.stereotype.Component;
import java.util.List;

@Component
public class StoredComparisonBatchSource implements ComparisonBatchSource {

    private final List<ComparisonDocumentSource> documentSources;
    private final List<ComparisonCustomerSource> customerSources;
    private final DocumentCodec documents;

    public StoredComparisonBatchSource(List<ComparisonDocumentSource> documentSources,
            List<ComparisonCustomerSource> customerSources, DocumentCodec documents) {
        this.documentSources = List.copyOf(documentSources);
        this.customerSources = List.copyOf(customerSources);
        this.documents = documents;
    }

    @Override
    public ArmBatchFingerprint capture(String arm, ComparisonExportSelection selection) {
        List<String> ids = selection.targetIds().stream().sorted().toList();
        List<BatchFingerprintItem> items = selection.resourceType() == ExportResourceType.DOCUMENT
                ? documentItems(arm, ids) : customerItems(arm, ids);
        boolean complete = items.size() == ids.size() && items.stream()
                .allMatch(value -> "CAPTURED".equals(value.state()) && value.sourceSha256() != null);
        return new ArmBatchFingerprint(arm, complete ? "CAPTURED" : "UNAVAILABLE", selection.resourceType(), items,
                complete ? documents.hash(documents.write(items)) : null);
    }

    private List<BatchFingerprintItem> documentItems(String arm, List<String> ids) {
        ComparisonDocumentSource source = documentSources.stream()
                .filter(value -> arm.equals(value.capture(ids.get(0)).arm())).findFirst().orElseThrow();
        return ids.stream().map(id -> {
            var value = source.capture(id);
            return new BatchFingerprintItem(id, value.state(), value.version(), value.projectId(),
                    value.title(), value.sourceSha256());
        }).toList();
    }

    private List<BatchFingerprintItem> customerItems(String arm, List<String> ids) {
        ComparisonCustomerSource source = customerSources.stream()
                .filter(value -> arm.equals(value.capture(ids.get(0)).arm())).findFirst().orElseThrow();
        return ids.stream().map(id -> {
            var value = source.capture(id);
            return new BatchFingerprintItem(id, value.state(), value.version(), value.projectId(),
                    value.name(), value.sourceSha256());
        }).toList();
    }
}
