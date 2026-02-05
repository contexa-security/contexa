package io.contexa.contexacore.std.rag.service;

import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;

import java.util.List;
import java.util.Map;

public interface VectorOperations {

    void storeDocument(Document document);

    void storeDocuments(List<Document> documents);

    List<Document> searchSimilar(String query);

    List<Document> searchSimilar(String query, Map<String, Object> filters);

    List<Document> searchSimilar(SearchRequest searchRequest);

    void deleteDocuments(List<String> documentIds);

    class VectorStoreException extends RuntimeException {
        public VectorStoreException(String message) {
            super(message);
        }

        public VectorStoreException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
