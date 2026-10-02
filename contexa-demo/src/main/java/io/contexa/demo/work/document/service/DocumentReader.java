package io.contexa.demo.work.document.service;

import io.contexa.demo.work.document.dto.DocumentReadResult;
import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;

public interface DocumentReader {

    DocumentReadResult read(BusinessRequestSnapshot snapshot);
}
