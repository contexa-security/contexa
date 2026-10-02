package io.contexa.demo.work.document.repository;

import io.contexa.demo.work.document.dto.DocumentReadResult;

public interface DocumentReadRepository {

    void append(DocumentReadResult result);
}
