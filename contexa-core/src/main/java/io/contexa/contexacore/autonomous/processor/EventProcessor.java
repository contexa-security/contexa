package io.contexa.contexacore.autonomous.processor;

/**
 * 이벤트 처리기 인터페이스
 * 
 * Strategy 패턴을 적용한 이벤트 처리 전략 인터페이스입니다.
 * 다양한 이벤트 처리 로직을 캡슐화하고 런타임에 교체 가능하도록 합니다.
 * 
 * @param <T> 처리할 이벤트 타입
 * @since 1.0
 * @author AI3Security
 */
public interface EventProcessor<T> {
    
    /**
     * 이벤트 처리
     * 
     * @param event 처리할 이벤트
     * @return 처리된 이벤트 (null 가능 - 필터링된 경우)
     */
    T process(T event);
    
    /**
     * 프로세서 우선순위
     * 숫자가 높을수록 먼저 실행됨
     * 
     * @return 우선순위 (기본값: 0)
     */
    default int getPriority() {
        return 0;
    }
    
    /**
     * 프로세서 이름
     * 
     * @return 프로세서 식별 이름
     */
    default String getName() {
        return this.getClass().getSimpleName();
    }
    
    /**
     * 프로세서 활성 상태
     * 
     * @return 활성화 여부
     */
    default boolean isEnabled() {
        return true;
    }
    
    /**
     * 배치 처리 지원
     * 성능 최적화를 위한 배치 처리
     * 
     * @param events 처리할 이벤트 목록
     * @return 처리된 이벤트 목록
     */
    default java.util.List<T> processBatch(java.util.List<T> events) {
        if (events == null || events.isEmpty()) {
            return events;
        }
        
        java.util.List<T> processed = new java.util.ArrayList<>();
        for (T event : events) {
            T result = process(event);
            if (result != null) {
                processed.add(result);
            }
        }
        return processed;
    }
}