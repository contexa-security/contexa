package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;

import java.util.List;

/**
 * sandbox 전용 UnifiedVectorService wrapper.
 *
 * production retrieval/storage 로직은 그대로 사용하고,
 * sandbox audit 저장소에 raw 검색 결과와 저장 문서만 남긴다.
 */
public class SandboxObservedUnifiedVectorService extends UnifiedVectorService {

    private final SandboxRetrievalAuditStore sandboxRetrievalAuditStore;

    public SandboxObservedUnifiedVectorService(
            PgVectorStoreProperties properties,
            VectorStoreCacheLayer cacheLayer,
            VectorStore vectorStore,
            SandboxRetrievalAuditStore sandboxRetrievalAuditStore) {
        super(properties, cacheLayer, vectorStore);
        this.sandboxRetrievalAuditStore = sandboxRetrievalAuditStore;
    }

    @Override
    public void storeDocument(Document document) {
        super.storeDocument(document);
        sandboxRetrievalAuditStore.recordStore(document);
    }

    @Override
    public void storeDocuments(List<Document> documents) {
        super.storeDocuments(documents);
        if (documents != null) {
            documents.forEach(sandboxRetrievalAuditStore::recordStore);
        }
    }

    @Override
    public List<Document> searchSimilar(SearchRequest searchRequest) {
        List<Document> documents = super.searchSimilar(searchRequest);
        sandboxRetrievalAuditStore.recordSearch(searchRequest, documents);
        return documents;
    }
}
