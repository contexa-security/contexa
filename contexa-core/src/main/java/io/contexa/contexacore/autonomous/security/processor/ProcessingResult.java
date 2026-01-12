package io.contexa.contexacore.autonomous.security.processor;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Path Processor 처리 결과
 *
 * Cold Path(AI Analysis)에서 분석 결과를 SecurityPlaneAgent로 반환하기 위한 DTO.
 * 프로젝트 센티넬 아키텍처에 따라 Path Processor는 분석만 수행하고,
 * Trust Score 업데이트는 SecurityPlaneAgent가 중앙에서 관리합니다.
 *
 * AI Native 아키텍처: LLM riskScore를 직접 사용
 *
 * @author contexa Platform
 * @since 1.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProcessingResult {

    /**
     * 처리 성공 여부
     */
    private boolean success;


    /**
     * LLM 분석 결과 위험 점수 (AI Native)
     * 0.0 ~ 1.0 범위 (LLM이 직접 계산한 값, 가공 없이 사용)
     *
     * 용도:
     * - Redis threat_score에 직접 저장
     * - 시간 감쇠, magnitude 곱셈 없이 그대로 사용
     * - LLM의 판단을 100% 신뢰
     */
    private double riskScore;

    /**
     * 현재 계산된 위험 수준
     * 0.0 ~ 1.0 범위
     */
    private double currentRiskLevel;
    
    /**
     * 처리 경로 (COLD_PATH, BYPASS)
     */
    private ProcessingPath processingPath;
    
    /**
     * 분석 데이터
     * AI 분석 결과, 패턴 매칭 결과 등
     */
    @Builder.Default
    private Map<String, Object> analysisData = new HashMap<>();
    
    /**
     * 탐지된 위협 지표들
     */
    private List<String> threatIndicators;
    
    /**
     * 인시던트 생성 필요 여부
     */
    private boolean requiresIncident;
    
    /**
     * 인시던트 심각도 (인시던트 필요시)
     */
    private IncidentSeverity incidentSeverity;
    
    /**
     * 처리 시간 (밀리초)
     */
    private long processingTimeMs;
    
    /**
     * 처리 완료 시간
     */
    private LocalDateTime processedAt;
    
    /**
     * AI 분석 수행 여부 (Cold Path)
     */
    private boolean aiAnalysisPerformed;
    
    /**
     * AI 분석 레벨 (Cold Path, 2-Tier 시스템)
     * 1: Layer1 - 경량 로컬 모델, 빠른 응답 (~100ms)
     * 2: Layer2 - 고성능 모델, 심층 분석 (~5s)
     */
    private int aiAnalysisLevel;
    
    /**
     * 추가 액션 제안
     */
    private List<String> recommendedActions;
    
    /**
     * 처리 상태
     */
    private ProcessingStatus status;

    /**
     * 오류 메시지 (실패시)
     */
    private String errorMessage;

    /**
     * 이상 탐지 여부
     * Cold Path에서 AI 분석 결과로 설정
     */
    private boolean anomaly;

    /**
     * 실행된 액션 목록
     */
    private List<String> executedActions;

    /**
     * 메타데이터
     */
    @Builder.Default
    private Map<String, Object> metadata = new HashMap<>();

    /**
     * 처리 메시지
     */
    private String message;
    
    /**
     * 처리 경로 열거형
     * AI Native 아키텍처: Cold Path(LLM 분석)가 기본
     */
    public enum ProcessingPath {
        COLD_PATH("Cold Path - AI Analysis"),
        BYPASS("Bypass - No Processing");

        private final String description;

        ProcessingPath(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 인시던트 심각도
     */
    public enum IncidentSeverity {
        LOW(1, "Low severity incident"),
        MEDIUM(2, "Medium severity incident"),
        HIGH(3, "High severity incident"),
        CRITICAL(4, "Critical severity incident");
        
        private final int level;
        private final String description;
        
        IncidentSeverity(int level, String description) {
            this.level = level;
            this.description = description;
        }
        
        public int getLevel() {
            return level;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 처리 상태
     */
    public enum ProcessingStatus {
        SUCCESS("Processing completed successfully"),
        PARTIAL_SUCCESS("Processing partially completed"),
        FAILED("Processing failed"),
        TIMEOUT("Processing timeout"),
        SKIPPED("Processing skipped");
        
        private final String description;
        
        ProcessingStatus(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * 빠른 생성을 위한 정적 팩토리 메서드 - 성공
     */
    public static ProcessingResult success(ProcessingPath path, double riskScore) {
        return ProcessingResult.builder()
                .processingPath(path)
                .riskScore(riskScore)
                .success(true)
                .status(ProcessingStatus.SUCCESS)
                .processedAt(LocalDateTime.now())
                .build();
    }

    /**
     * 빠른 생성을 위한 정적 팩토리 메서드 - 실패
     */
    public static ProcessingResult failure(ProcessingPath path, String error) {
        return ProcessingResult.builder()
                .processingPath(path)
                .success(false)
                .status(ProcessingStatus.FAILED)
                .errorMessage(error)
                .processedAt(LocalDateTime.now())
                .build();
    }


    /**
     * 성공 여부 getter (호환성)
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * 실행된 액션 getter (호환성)
     */
    public List<String> getExecutedActions() {
        return executedActions;
    }

    /**
     * 메타데이터 getter (호환성)
     */
    public Map<String, Object> getMetadata() {
        return metadata;
    }

    /**
     * 인시던트 심각도 getter (호환성)
     */
    public String getIncidentSeverity() {
        if (incidentSeverity != null) {
            return incidentSeverity.name();
        }
        return null;
    }
    
    /**
     * 분석 데이터 추가 헬퍼 메서드
     */
    public void addAnalysisData(String key, Object value) {
        if (this.analysisData == null) {
            this.analysisData = new HashMap<>();
        }
        this.analysisData.put(key, value);
    }
    
    /**
     * 처리 시간 계산 및 설정
     */
    public void setProcessingComplete(long startTimeMs) {
        this.processingTimeMs = System.currentTimeMillis() - startTimeMs;
        this.processedAt = LocalDateTime.now();
    }

    /**
     * 이상 탐지 여부 확인
     *
     * @return 이상 탐지되었으면 true
     */
    public boolean isAnomaly() {
        return anomaly;
    }

    /**
     * 이상 탐지 여부 설정
     *
     * @param anomaly 이상 탐지 여부
     */
    public void setAnomaly(boolean anomaly) {
        this.anomaly = anomaly;
    }
}