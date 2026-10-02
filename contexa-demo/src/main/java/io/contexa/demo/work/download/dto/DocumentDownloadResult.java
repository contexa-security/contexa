package io.contexa.demo.work.download.dto;

import io.contexa.demo.work.shared.dto.BusinessFile;
public record DocumentDownloadResult(BusinessFile file, boolean reused) {
}
