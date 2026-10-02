package io.contexa.demo.work.catalog.service.impl;

import io.contexa.demo.work.catalog.service.WorkCatalog;
import io.contexa.demo.work.document.dto.DocumentSummary;
import io.contexa.demo.work.document.repository.DocumentRepository;
import io.contexa.demo.work.project.dto.ProjectView;
import io.contexa.demo.work.project.repository.ProjectRepository;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
@Profile({"baseline", "contexa"})
public class DefaultWorkCatalog implements WorkCatalog {

    private final ProjectRepository projects;
    private final DocumentRepository documents;

    public DefaultWorkCatalog(ProjectRepository projects, DocumentRepository documents) {
        this.projects = projects;
        this.documents = documents;
    }

    public List<ProjectView> projects(String username) {
        return projects.list(username);
    }

    public List<DocumentSummary> documents(String projectId, String search) {
        if (search.length() > 120) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Search is too long");
        }
        return documents.search(projectId, search.trim());
    }

    public DocumentSummary document(String id) {
        DocumentSummary document = documents.find(id);
        if (document == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Document not found");
        }
        return document;
    }
}
