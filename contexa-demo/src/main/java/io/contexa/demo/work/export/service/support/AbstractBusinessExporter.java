package io.contexa.demo.work.export.service.support;

import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.export.dto.ExportDownloadResult;
import io.contexa.demo.work.export.dto.ExportInput;
import io.contexa.demo.work.export.dto.ExportRequestSnapshot;
import io.contexa.demo.work.export.repository.ExportRepository;
import io.contexa.demo.work.export.service.BusinessExporter;
import io.contexa.demo.work.export.service.ExportContentWriter;
import io.contexa.demo.work.shared.service.support.AbstractBusinessOperation;

import java.util.List;

public abstract class AbstractBusinessExporter extends AbstractBusinessOperation implements BusinessExporter {

    private final ExportRepository exports;
    private final List<ExportContentWriter> writers;

    protected AbstractBusinessExporter(ExportRepository exports, List<ExportContentWriter> writers,
            ApprovalUsageQuery approvals) {
        super(approvals);
        this.exports = exports;
        this.writers = List.copyOf(writers);
    }

    protected ExportDownloadResult prepareFile(ExportRequestSnapshot snapshot, ExportInput input) {
        requireApproval(snapshot);
        ExportContentWriter writer = writers.stream().filter(candidate -> candidate.resourceType() == input.resourceType())
                .findFirst().orElseThrow(() -> new IllegalStateException("Export format is unavailable"));
        return exports.saveOrReuse(snapshot, input, () -> writer.write(snapshot, input.language()));
    }
}
