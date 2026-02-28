package io.contexa.contexaiam.aiam.components.retriever;

import io.contexa.contexacore.properties.ContexaRagProperties;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.ai.vectorstore.VectorStore;

import java.util.List;
import java.util.Map;

@Slf4j
public class ConditionTemplateContextRetriever extends ContextRetriever {

    private final ContextRetrieverRegistry registry;

    public ConditionTemplateContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry registry,
            ContexaRagProperties ragProperties) {
        super(vectorStore, ragProperties);
        this.registry = registry;
    }

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        registry.registerRetriever(ConditionTemplateContext.class, this);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        if (request.getContext() instanceof ConditionTemplateContext) {
            return new ContextRetrievalResult(
                    "",
                    List.of(),
                    Map.of("retrieverType", "ConditionTemplateContextRetriever", "timestamp", System.currentTimeMillis())
            );
        }
        return super.retrieveContext(request);
    }
}
