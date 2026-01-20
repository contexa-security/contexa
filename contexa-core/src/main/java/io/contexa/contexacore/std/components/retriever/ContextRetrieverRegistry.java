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
        log.info("ContextRetrieverRegistry 초기화 - 기본 Retriever: {}", 
                defaultRetriever.getClass().getSimpleName());
    }
    
    
    public void registerRetriever(Class<? extends DomainContext> contextType, ContextRetriever retriever) {
        retrieverMap.put(contextType, retriever);
        log.info("ContextRetriever 등록: {} → {}", 
                contextType.getSimpleName(), 
                retriever.getClass().getSimpleName());
    }
    
    
    public ContextRetriever getRetriever(Class<? extends DomainContext> contextType) {
        
        ContextRetriever retriever = retrieverMap.get(contextType);
        if (retriever != null) {
            log.debug("정확한 타입 매칭: {} → {}", 
                     contextType.getSimpleName(), 
                     retriever.getClass().getSimpleName());
            return retriever;
        }
        
        
        for (Map.Entry<Class<? extends DomainContext>, ContextRetriever> entry : retrieverMap.entrySet()) {
            if (entry.getKey().isAssignableFrom(contextType)) {
                log.debug("상위 타입 매칭: {} → {} (via {})", 
                         contextType.getSimpleName(),
                         entry.getValue().getClass().getSimpleName(),
                         entry.getKey().getSimpleName());
                return entry.getValue();
            }
        }
        
        
        log.debug("기본 Retriever 사용: {} → {}", 
                 contextType.getSimpleName(), 
                 defaultRetriever.getClass().getSimpleName());
        return defaultRetriever;
    }
    
    
    @SuppressWarnings("unchecked")
    public ContextRetriever getRetriever(DomainContext context) {
        return getRetriever((Class<? extends DomainContext>) context.getClass());
    }
    
    
    public void printRegisteredRetrievers() {
        log.info("등록된 ContextRetriever 목록:");
        log.info("  기본: {}", defaultRetriever.getClass().getSimpleName());
        retrieverMap.forEach((contextType, retriever) -> 
            log.info("  {}: {}", 
                    contextType.getSimpleName(), 
                    retriever.getClass().getSimpleName())
        );
    }
}