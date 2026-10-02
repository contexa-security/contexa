package io.contexa.demo.work.download.service;

import io.contexa.demo.work.download.dto.DocumentDownloadInput;
import io.contexa.demo.work.download.dto.DocumentDownloadResult;
import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;

public interface DocumentDownloader {

    DocumentDownloadResult download(BusinessRequestSnapshot snapshot, DocumentDownloadInput input);
}
