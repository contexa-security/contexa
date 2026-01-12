package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import org.springframework.context.ApplicationEvent;

/**
 * Cold/Hot Path 처리 완료 시 발생하는 이벤트
 *
 * 이 이벤트는 SecurityEventProcessingOrchestrator가 보안 이벤트 처리를 완료했을 때 발행됩니다.
 * 자율 학습 시스템이 모든 처리 결과를 학습 데이터로 활용하여 정책을 진화시킵니다.
 *
 * **학습 데이터 수집 전략**:
 * - Hot Path (실시간): REALTIME_BLOCK, PASS_THROUGH 결과 학습
 * - Cold Path (AI 분석): Layer1/2/3 분석 결과 학습
 * - 모든 위협 레벨 (CRITICAL, HIGH, MEDIUM, LOW, INFO) 학습 대상
 * - 학습률 목표: 95%+ (현재 0.016% → 개선)
 *
 * @author contexa
 * @since 1.0.0
 */
public class ProcessingCompletedEvent extends ApplicationEvent {

    private final SecurityEvent originalEvent;
    private final ProcessingResult result;
    private final ProcessingMode mode;
    private final ProcessingLayer layer;
    private final long processingTimeMs;
    private final double accuracy;

    /**
     * 처리 완료 이벤트 생성자
     *
     * @param source 이벤트 발생 소스 (일반적으로 SecurityEventProcessingOrchestrator)
     * @param originalEvent 원본 보안 이벤트
     * @param result 처리 결과 (위협 레벨, 추천 액션, 분석 데이터 등)
     * @param mode 처리 모드 (REALTIME_BLOCK, PASS_THROUGH, AI_ANALYSIS 등)
     * @param layer 처리 계층 (LAYER1, LAYER2) - 2-Tier 시스템
     * @param processingTimeMs 처리 시간(밀리초) - 성능 학습용
     * @param accuracy 사후 검증 점수 (0.0~1.0) - 향후 피드백 루프용, 현재는 0.0 기본값
     */
    public ProcessingCompletedEvent(Object source, SecurityEvent originalEvent,
                                   ProcessingResult result, ProcessingMode mode,
                                   ProcessingLayer layer, long processingTimeMs,
                                   double accuracy) {
        super(source);
        this.originalEvent = originalEvent;
        this.result = result;
        this.mode = mode;
        this.layer = layer;
        this.processingTimeMs = processingTimeMs;
        this.accuracy = accuracy;
    }

    /**
     * 간편 생성자 (accuracy 없이)
     *
     * @param source 이벤트 발생 소스
     * @param originalEvent 원본 보안 이벤트
     * @param result 처리 결과
     * @param mode 처리 모드
     * @param layer 처리 계층
     * @param processingTimeMs 처리 시간(밀리초)
     */
    public ProcessingCompletedEvent(Object source, SecurityEvent originalEvent,
                                   ProcessingResult result, ProcessingMode mode,
                                   ProcessingLayer layer, long processingTimeMs) {
        this(source, originalEvent, result, mode, layer, processingTimeMs, 0.0);
    }

    // Getters
    public SecurityEvent getOriginalEvent() {
        return originalEvent;
    }

    public ProcessingResult getResult() {
        return result;
    }

    public ProcessingMode getMode() {
        return mode;
    }

    public ProcessingLayer getLayer() {
        return layer;
    }

    public long getProcessingTimeMs() {
        return processingTimeMs;
    }

    public double getAccuracy() {
        return accuracy;
    }

    /**
     * Hot Path 처리 결과인지 확인
     * AI Native: REALTIME_BLOCK만 Hot Path로 간주
     *
     * @return Hot Path이면 true
     */
    public boolean isHotPath() {
        return mode == ProcessingMode.REALTIME_BLOCK;
    }

    /**
     * Cold Path 처리 결과인지 확인
     *
     * @return Cold Path이면 true (AI_ANALYSIS, SOAR_ORCHESTRATION 등)
     */
    public boolean isColdPath() {
        return mode == ProcessingMode.AI_ANALYSIS ||
               mode == ProcessingMode.SOAR_ORCHESTRATION ||
               mode == ProcessingMode.AWAIT_APPROVAL;
    }

    /**
     * 학습 가치가 높은 이벤트인지 확인
     *
     * @return 학습 가치가 높으면 true (위협 탐지, 이상 징후, Layer2+ 분석)
     */
    public boolean isHighValueForLearning() {
        // Layer 2 이상 분석 결과
        if (layer.ordinal() >= ProcessingLayer.LAYER2.ordinal()) {
            return true;
        }

        // 이상 징후 탐지
        if (result != null && result.isAnomaly()) {
            return true;
        }

        // 위협 지표 발견
        if (result != null && result.getThreatIndicators() != null &&
            !result.getThreatIndicators().isEmpty()) {
            return true;
        }

        // 인시던트 생성 필요
        if (result != null && result.isRequiresIncident()) {
            return true;
        }

        return false;
    }

    @Override
    public String toString() {
        return String.format("ProcessingCompletedEvent[eventId=%s, mode=%s, layer=%s, timeMs=%d, accuracy=%.2f, highValue=%s]",
            originalEvent != null ? originalEvent.getEventId() : "null",
            mode, layer, processingTimeMs, accuracy, isHighValueForLearning());
    }

    /**
     * 처리 계층 열거형 (2-Tier 시스템)
     */
    public enum ProcessingLayer {
        LAYER1("Layer1 - Fast Filter, Local Model (~100ms)"),
        LAYER2("Layer2 - Expert Analysis, High-Performance Model (~5s)"),
        UNKNOWN("Unknown Layer");

        private final String description;

        ProcessingLayer(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }

        /**
         * aiAnalysisLevel을 ProcessingLayer로 변환 (2-Tier 시스템)
         *
         * @param level AI 분석 레벨 (1, 2)
         * @return 대응하는 ProcessingLayer
         */
        public static ProcessingLayer fromLevel(int level) {
            switch (level) {
                case 1: return LAYER1;
                case 2: return LAYER2;
                default: return UNKNOWN;
            }
        }
    }
}
