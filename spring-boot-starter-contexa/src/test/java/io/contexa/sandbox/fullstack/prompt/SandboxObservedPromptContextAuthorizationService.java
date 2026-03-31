package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.std.security.AuthorizedPromptContext;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.springframework.ai.document.Document;
import org.springframework.lang.Nullable;

import java.util.List;

/**
 * sandbox 전용 prompt authorization wrapper.
 *
 * 목적:
 * - raw retrieval 결과가 있었다면 authorize 이후 몇 건이 허용/거부되는지 기록
 * - denied reason까지 남겨서 relatedDocuments=0 원인을 search/authorize 경계로 분해
 */
public class SandboxObservedPromptContextAuthorizationService extends PromptContextAuthorizationService {

    private final SandboxRetrievalAuditStore sandboxRetrievalAuditStore;

    public SandboxObservedPromptContextAuthorizationService(
            SandboxRetrievalAuditStore sandboxRetrievalAuditStore) {
        this.sandboxRetrievalAuditStore = sandboxRetrievalAuditStore;
    }

    @Override
    public AuthorizedPromptContext authorize(SecurityEvent event, @Nullable String retrievalPurpose, List<Document> documents) {
        AuthorizedPromptContext authorizedPromptContext = super.authorize(event, retrievalPurpose, documents);
        sandboxRetrievalAuditStore.recordAuthorization(event, retrievalPurpose, documents, authorizedPromptContext);
        return authorizedPromptContext;
    }
}
