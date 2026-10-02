package io.contexa.demo.work.download.repository;

import io.contexa.demo.work.download.dto.DocumentDownloadInput;
import io.contexa.demo.work.download.dto.DocumentDownloadResult;
import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;

public interface DocumentDownloadRepository {

    DocumentDownloadResult saveOrReuse(BusinessRequestSnapshot snapshot, DocumentDownloadInput input, String content);
}
