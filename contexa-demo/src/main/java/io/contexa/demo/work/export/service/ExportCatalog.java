package io.contexa.demo.work.export.service;

import io.contexa.demo.work.export.dto.ExportResourceType;
import io.contexa.demo.work.export.dto.ExportTarget;

import java.util.List;

public interface ExportCatalog {

    List<ExportTarget> resolve(ExportResourceType type, List<String> ids);
}
