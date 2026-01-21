package io.contexa.contexacore.std.components.retriever;

import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Slf4j
public class ContextRetrieverRegistry {
    
    private final Map<Class<? extends DomainContext>, ContextRetriever> retrieverMap = new HashMap<>();
    private final ContextRetriever defaultRetriever;
    
    public ContextRetrieverRegistry(ContextRetriever defaultRetriever) {
        this.defaultRetriever = defaultRetriever;
            }

    public void registerRetriever(Class<? extends DomainContext> contextType, ContextRetriever retriever) {
        retrieverMap.put(contextType, retriever);
            }

    public ContextRetriever getRetriever(Class<? extends DomainContext> contextType) {
        
        ContextRetriever retriever = retrieverMap.get(contextType);
        if (retriever != null) {
                        return retriever;
        }

        for (Map.Entry<Class<? extends DomainContext>, ContextRetriever> entry : retrieverMap.entrySet()) {
            if (entry.getKey().isAssignableFrom(contextType)) {
                                return entry.getValue();
            }
        }

                return defaultRetriever;
    }

    @SuppressWarnings("unchecked")
    public ContextRetriever getRetriever(DomainContext context) {
        return getRetriever((Class<? extends DomainContext>) context.getClass());
    }

    public void printRegisteredRetrievers() {
        retrieverMap.forEach((contextType, retriever) ->
                log.info("  {}: {}",
                        contextType.getSimpleName(),
                        retriever.getClass().getSimpleName())
        );
    }
}