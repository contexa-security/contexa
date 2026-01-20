package io.contexa.contexacore.std.rag.service;

import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;


public interface VectorOperations {
    
    
    void storeDocument(Document document);
    
    
    void storeDocuments(List<Document> documents);
    
    
    CompletableFuture<Void> storeDocumentAsync(Document document);
    
    
    CompletableFuture<Void> storeDocumentsAsync(List<Document> documents);
    
    
    List<Document> searchSimilar(String query);
    
    
    List<Document> searchSimilar(String query, Map<String, Object> filters);
    
    
    List<Document> searchSimilar(SearchRequest searchRequest);
    
    
    List<Document> searchByTimeRange(String query, LocalDateTime startTime, 
                                    LocalDateTime endTime, String documentType);
    
    
    void deleteDocuments(List<String> documentIds);
    
    
    void updateDocuments(List<Document> documents);
    
    
    Map<String, Object> getStatistics();
    
    
    class VectorStoreException extends RuntimeException {
        public VectorStoreException(String message) {
            super(message);
        }
        
        public VectorStoreException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}