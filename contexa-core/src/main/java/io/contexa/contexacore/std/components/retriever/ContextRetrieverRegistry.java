package io.contexa.contexacore.std.components.retriever;

import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * ContextRetriever Registry - OCP 준수 설계
 * 
 * Open-Closed Principle 완벽 준수
 * Context 타입별 ContextRetriever 동적 등록/조회
 * 확장성: 새로운 ContextRetriever 추가 시 기존 코드 수정 불필요
 * 
 * **설계 원칙:**
 * - Registry Pattern: Context 타입 → ContextRetriever 매핑
 * - Dynamic Dispatch: 런타임에 적절한 Retriever 선택
 * - Fallback Strategy: 등록되지 않은 타입은 기본 Retriever 사용
 */
@Slf4j
@Component
public class ContextRetrieverRegistry {
    
    private final Map<Class<? extends DomainContext>, ContextRetriever> retrieverMap = new HashMap<>();
    private final ContextRetriever defaultRetriever;
    
    public ContextRetrieverRegistry(@Qualifier("contextRetriever") ContextRetriever defaultRetriever) {
        this.defaultRetriever = defaultRetriever;
        log.info("ContextRetrieverRegistry 초기화 - 기본 Retriever: {}", 
                defaultRetriever.getClass().getSimpleName());
    }
    
    /**
     * Context 타입별 ContextRetriever 등록
     * 
     * @param contextType 지원하는 Context 타입
     * @param retriever 해당 타입을 처리할 ContextRetriever
     */
    public void registerRetriever(Class<? extends DomainContext> contextType, ContextRetriever retriever) {
        retrieverMap.put(contextType, retriever);
        log.info("ContextRetriever 등록: {} → {}", 
                contextType.getSimpleName(), 
                retriever.getClass().getSimpleName());
    }
    
    /**
     * Context 타입에 적절한 ContextRetriever 조회
     * 
     * @param contextType Context 타입
     * @return 적절한 ContextRetriever (없으면 기본 Retriever)
     */
    public ContextRetriever getRetriever(Class<? extends DomainContext> contextType) {
        // 1. 정확한 타입 매칭 시도
        ContextRetriever retriever = retrieverMap.get(contextType);
        if (retriever != null) {
            log.debug("정확한 타입 매칭: {} → {}", 
                     contextType.getSimpleName(), 
                     retriever.getClass().getSimpleName());
            return retriever;
        }
        
        // 2. 상위 타입 매칭 시도 (상속 관계 고려)
        for (Map.Entry<Class<? extends DomainContext>, ContextRetriever> entry : retrieverMap.entrySet()) {
            if (entry.getKey().isAssignableFrom(contextType)) {
                log.debug("상위 타입 매칭: {} → {} (via {})", 
                         contextType.getSimpleName(),
                         entry.getValue().getClass().getSimpleName(),
                         entry.getKey().getSimpleName());
                return entry.getValue();
            }
        }
        
        // 3. Fallback: 기본 Retriever 사용
        log.debug("기본 Retriever 사용: {} → {}", 
                 contextType.getSimpleName(), 
                 defaultRetriever.getClass().getSimpleName());
        return defaultRetriever;
    }
    
    /**
     * Context 인스턴스로 적절한 ContextRetriever 조회
     * 
     * @param context Context 인스턴스
     * @return 적절한 ContextRetriever
     */
    @SuppressWarnings("unchecked")
    public ContextRetriever getRetriever(DomainContext context) {
        return getRetriever((Class<? extends DomainContext>) context.getClass());
    }
    
    /**
     * 등록된 모든 Retriever 정보 출력 (디버깅용)
     */
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