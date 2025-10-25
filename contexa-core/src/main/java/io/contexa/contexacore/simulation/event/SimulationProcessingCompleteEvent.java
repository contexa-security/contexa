package io.contexa.contexacore.simulation.event;

import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * 시뮬레이션 보안 이벤트 처리 완료 이벤트
 *
 * SecurityPlaneAgent가 시뮬레이션 이벤트 처리를 완료했을 때 발행되는 이벤트입니다.
 * 실제 보안 시스템의 응답(차단/탐지)을 포함합니다.
 *
 * @author contexa
 * @since 1.0.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SimulationProcessingCompleteEvent {

    /**
     * 보안 이벤트 ID
     */
    private String eventId;

    /**
     * 시뮬레이션 공격 ID
     */
    private String attackId;

    /**
     * 공격 타입
     */
    private String attackType;

    /**
     * 대상 사용자
     */
    private String targetUser;

    /**
     * 공격 출발 IP
     */
    private String sourceIp;

    /**
     * 위협 탐지 여부 (AI가 위협으로 판단했는지)
     */
    private boolean detected;

    /**
     * 차단 여부 (실제 차단 액션이 실행되었는지)
     */
    private boolean blocked;

    /**
     * 위험 점수 (0.0 ~ 1.0)
     */
    private double riskScore;

    /**
     * 신뢰도 점수 (0.0 ~ 1.0)
     */
    private double confidenceScore;

    /**
     * 처리 모드 (HOT_PATH, COLD_PATH, REALTIME_BLOCK 등)
     */
    private ProcessingMode processingMode;

    /**
     * 처리 결과 상세
     */
    private ProcessingResult processingResult;

    /**
     * 실행된 보안 액션 목록
     */
    private Map<String, String> responseActions;

    /**
     * 처리 소요 시간 (밀리초)
     */
    private long processingTimeMs;

    /**
     * AI 분석 소요 시간 (밀리초)
     */
    private long aiAnalysisTimeMs;

    /**
     * 처리 완료 시각
     */
    private LocalDateTime processedAt;

    /**
     * 시뮬레이션 모드 (UNPROTECTED, PROTECTED)
     */
    private SimulationMode simulationMode;

    /**
     * 추가 메타데이터
     */
    private Map<String, Object> metadata;

    /**
     * 시뮬레이션 모드 열거형
     */
    public enum SimulationMode {
        /**
         * 무방비 모드 - 보안 시스템 비활성화
         */
        UNPROTECTED,

        /**
         * 방어 모드 - 보안 시스템 활성화
         */
        PROTECTED
    }
}