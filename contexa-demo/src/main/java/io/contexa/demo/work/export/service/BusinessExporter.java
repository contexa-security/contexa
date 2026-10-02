package io.contexa.demo.work.export.service;

import io.contexa.demo.work.export.dto.ExportDownloadResult;
import io.contexa.demo.work.export.dto.ExportInput;
import io.contexa.demo.work.export.dto.ExportRequestSnapshot;

public interface BusinessExporter {

    ExportDownloadResult export(ExportRequestSnapshot snapshot, ExportInput input);
}
