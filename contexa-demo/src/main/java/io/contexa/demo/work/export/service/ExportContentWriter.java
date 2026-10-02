package io.contexa.demo.work.export.service;

import io.contexa.demo.work.download.dto.DocumentLanguage;
import io.contexa.demo.work.export.dto.ExportContent;
import io.contexa.demo.work.export.dto.ExportRequestSnapshot;
import io.contexa.demo.work.export.dto.ExportResourceType;

public interface ExportContentWriter {

    ExportResourceType resourceType();

    ExportContent write(ExportRequestSnapshot snapshot, DocumentLanguage language);
}
