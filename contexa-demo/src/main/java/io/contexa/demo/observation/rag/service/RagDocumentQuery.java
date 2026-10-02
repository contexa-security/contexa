package io.contexa.demo.observation.rag.service;

import io.contexa.demo.observation.rag.dto.RagDocumentReadback;

public interface RagDocumentQuery {

    RagDocumentReadback read(String documentId);
}
