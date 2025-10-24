package io.contexa.contexacore.std.llm.strategy;

import io.contexa.contexacore.std.llm.core.ExecutionContext;
import org.springframework.ai.chat.model.ChatModel;

/**
 * 모델 선택 전략 인터페이스
 * 
 * Strategy 패턴 적용:
 * - OCP: 새로운 선택 전략을 추가할 수 있음
 * - SRP: 모델 선택 로직만 담당
 * - DIP: 구체적인 선택 로직에 의존하지 않음
 */
public interface ModelSelectionStrategy {
    
    /**
     * ExecutionContext에 기반하여 최적의 ChatModel 선택
     * 
     * 선택 기준:
     * 1. 3계층 시스템 (tier 우선)
     * 2. SecurityTaskType 기반 선택
     * 3. 일반 TaskType 기반 선택
     * 4. 성능 요구사항 (timeout, fastResponse)
     * 5. 모델 선호도 (local vs cloud)
     * 
     * @param context 실행 컨텍스트
     * @return 선택된 ChatModel
     * @throws ModelSelectionException 모델 선택 실패 시
     */
    ChatModel selectModel(ExecutionContext context);
    
    /**
     * 전략이 지원하는 모델 타입들
     * @return 지원 모델 목록
     */
    java.util.Set<String> getSupportedModels();
    
    /**
     * 모델 가용성 확인
     * @param modelName 모델 이름
     * @return 사용 가능 여부
     */
    boolean isModelAvailable(String modelName);
    
    /**
     * 성능 메트릭 기반 모델 순위 조정
     * @param modelName 모델 이름
     * @param responseTime 응답 시간 (ms)
     * @param success 성공 여부
     */
    void recordModelPerformance(String modelName, long responseTime, boolean success);
}