package io.contexa.demo.work.export.repository;

import io.contexa.demo.work.export.dto.ExportContent;
import io.contexa.demo.work.export.dto.ExportDownloadResult;
import io.contexa.demo.work.export.dto.ExportInput;
import io.contexa.demo.work.export.dto.ExportRequestSnapshot;

import java.util.function.Supplier;

public interface ExportRepository {

    ExportDownloadResult saveOrReuse(ExportRequestSnapshot snapshot, ExportInput input,
            Supplier<ExportContent> content);
}
