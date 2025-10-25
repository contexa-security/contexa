package io.contexa.contexacore.autonomous.security.processor;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;

/**
 * Hot/Cold Path 프로세서 인터페이스
 * 
 * 위협 점수에 따라 Hot Path(빠른 처리) 또는 Cold Path(AI 진단)로
 * 보안 이벤트를 처리하는 프로세서들의 공통 인터페이스입니다.
 * 
 * - Hot Path: 낮은 위협(riskScore < 0.7), AI 없이 즉시 처리
 * - Cold Path: 높은 위협(riskScore >= 0.7), AI 진단 후 상세 분석
 * 
 * @author contexa Platform
 * @since 1.0
 */
public interface IPathProcessor {
    
    /**
     * 보안 이벤트 처리
     * 
     * @param event 보안 이벤트
     * @param riskScore 위협 점수 (0.0 ~ 1.0)
     * @return 처리 결과 (Trust Score 조정값, 분석 데이터 등)
     */
    ProcessingResult processEvent(SecurityEvent event, double riskScore);
    
    /**
     * 프로세서의 처리 모드 반환
     * 
     * @return ProcessingMode (REALTIME_* 또는 ASYNC_*)
     */
    ProcessingMode getProcessingMode();
    
    /**
     * 프로세서 이름 반환
     * 
     * @return 프로세서 식별자
     */
    String getProcessorName();
    
    /**
     * 프로세서 준비 상태 확인
     * 
     * @return 처리 가능 여부
     */
    default boolean isReady() {
        return true;
    }
    
    /**
     * 처리 통계 조회
     * 
     * @return 처리된 이벤트 수, 평균 처리 시간 등
     */
    default ProcessorStatistics getStatistics() {
        return ProcessorStatistics.empty();
    }
    
    /**
     * 프로세서 통계 정보
     */
    class ProcessorStatistics {
        private long processedCount;
        private double averageProcessingTime;
        private long lastProcessedTimestamp;
        
        public static ProcessorStatistics empty() {
            return new ProcessorStatistics();
        }
        
        // Getters and setters
        public long getProcessedCount() {
            return processedCount;
        }
        
        public void setProcessedCount(long processedCount) {
            this.processedCount = processedCount;
        }
        
        public double getAverageProcessingTime() {
            return averageProcessingTime;
        }
        
        public void setAverageProcessingTime(double averageProcessingTime) {
            this.averageProcessingTime = averageProcessingTime;
        }
        
        public long getLastProcessedTimestamp() {
            return lastProcessedTimestamp;
        }
        
        public void setLastProcessedTimestamp(long lastProcessedTimestamp) {
            this.lastProcessedTimestamp = lastProcessedTimestamp;
        }
    }
}