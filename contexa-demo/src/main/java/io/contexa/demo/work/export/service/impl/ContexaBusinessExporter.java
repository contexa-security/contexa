package io.contexa.demo.work.export.service.impl;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.export.dto.ExportDownloadResult;
import io.contexa.demo.work.export.dto.ExportInput;
import io.contexa.demo.work.export.dto.ExportRequestSnapshot;
import io.contexa.demo.work.export.repository.ExportRepository;
import io.contexa.demo.work.export.service.ExportContentWriter;
import io.contexa.demo.work.export.service.support.AbstractBusinessExporter;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Profile("contexa")
public class ContexaBusinessExporter extends AbstractBusinessExporter {

    public ContexaBusinessExporter(ExportRepository exports, List<ExportContentWriter> writers,
            ApprovalUsageQuery approvals) {
        super(exports, writers, approvals);
    }

    @Override
    @Protectable(sync = true)
    public ExportDownloadResult export(ExportRequestSnapshot snapshot, ExportInput input) {
        return prepareFile(snapshot, input);
    }
}
