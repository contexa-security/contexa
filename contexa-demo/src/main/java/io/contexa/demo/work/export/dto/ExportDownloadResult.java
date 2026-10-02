package io.contexa.demo.work.export.dto;

import io.contexa.demo.work.shared.dto.BusinessFile;

public record ExportDownloadResult(BusinessFile file, String contentType, int preparedItems, boolean reused) {
}
