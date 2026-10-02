package io.contexa.demo.work.catalog.service;

import io.contexa.demo.work.document.dto.DocumentSummary;
import io.contexa.demo.work.project.dto.ProjectView;

import java.util.List;

public interface WorkCatalog {

    List<ProjectView> projects(String username);

    List<DocumentSummary> documents(String projectId, String search);

    DocumentSummary document(String id);
}
