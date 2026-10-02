package io.contexa.demo.work.document.repository;

import io.contexa.demo.work.document.dto.DocumentBody;
import io.contexa.demo.work.document.dto.DocumentSummary;

import java.util.List;

public interface DocumentRepository {

    List<DocumentSummary> search(String projectId, String search);

    DocumentSummary find(String id);

    DocumentBody read(String id, int version);
}
