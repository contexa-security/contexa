package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.std.security.PromptContextAuthorizationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

/**
 * sandbox 전용 prompt trace 구성.
 *
 * 목적은 production 파이프라인을 건드리지 않고, 실제 런타임이 사용하는 PromptGenerator 경계에서
 * SecurityDecisionContext와 PromptGenerationResult 원본을 그대로 회수하는 것이다.
 *
 * 즉 이 설정은 synthetic 데이터를 만드는 것이 아니라,
 * 실제 웹 호출 -> 실제 비동기 분석 -> 실제 prompt 생성의 결과를 저장하는 역할만 한다.
 */
@TestConfiguration(proxyBeanMethods = false)
public class SandboxPromptTraceTestConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SandboxPromptTraceTestConfiguration.class);

    @Bean
    public SandboxRetrievalAuditStore sandboxRetrievalAuditStore() {
        return new SandboxRetrievalAuditStore();
    }

    @Bean
    public SandboxPromptTraceStore sandboxPromptTraceStore(
            SandboxRetrievalAuditStore sandboxRetrievalAuditStore) {
        return new SandboxPromptTraceStore(sandboxRetrievalAuditStore);
    }

    @Bean
    public SandboxVectorStoreIsolationSupport sandboxVectorStoreIsolationSupport(
            JdbcTemplate jdbcTemplate,
            @Autowired(required = false) VectorStoreCacheLayer cacheLayer) {
        return new SandboxVectorStoreIsolationSupport(jdbcTemplate, cacheLayer);
    }

    @Bean
    public SandboxLayer1ExecutionAspect sandboxLayer1ExecutionAspect(
            SandboxRetrievalAuditStore sandboxRetrievalAuditStore) {
        return new SandboxLayer1ExecutionAspect(sandboxRetrievalAuditStore);
    }

    @Bean
    public SandboxLayer1CompletionAspect sandboxLayer1CompletionAspect(
            SandboxPromptTraceStore sandboxPromptTraceStore) {
        return new SandboxLayer1CompletionAspect(sandboxPromptTraceStore);
    }

    @Bean
    @Primary
    public UnifiedVectorService sandboxObservedUnifiedVectorService(
            PgVectorStoreProperties properties,
            VectorStoreCacheLayer cacheLayer,
            VectorStore vectorStore,
            SandboxRetrievalAuditStore sandboxRetrievalAuditStore) {
        return new SandboxObservedUnifiedVectorService(
                properties,
                cacheLayer,
                vectorStore,
                sandboxRetrievalAuditStore);
    }

    @Bean
    @Primary
    public PromptContextAuthorizationService sandboxObservedPromptContextAuthorizationService(
            SandboxRetrievalAuditStore sandboxRetrievalAuditStore) {
        return new SandboxObservedPromptContextAuthorizationService(sandboxRetrievalAuditStore);
    }

    @Bean
    @Primary
    public PromptGenerator sandboxCapturingPromptGenerator(
            List<PromptTemplate> promptTemplates,
            SandboxPromptTraceStore sandboxPromptTraceStore) {

        return new PromptGenerator(promptTemplates) {
            @Override
            public PromptGenerationResult generatePrompt(
                    AIRequest<? extends DomainContext> request,
                    String contextInfo,
                    String systemMetadata) {

                PromptGenerationResult promptGenerationResult =
                        super.generatePrompt(request, contextInfo, systemMetadata);

                if (request != null && request.getContext() instanceof SecurityDecisionContext securityDecisionContext) {
                    log.info("[SandboxPromptTrace] Capturing prompt for userId={}, sessionId={}, eventId={}",
                            securityDecisionContext.getUserId(),
                            securityDecisionContext.getSessionId(),
                            securityDecisionContext.getSecurityEvent() != null
                                    ? securityDecisionContext.getSecurityEvent().getEventId()
                                    : null);
                    sandboxPromptTraceStore.capture(securityDecisionContext, promptGenerationResult);
                }

                return promptGenerationResult;
            }
        };
    }
}
