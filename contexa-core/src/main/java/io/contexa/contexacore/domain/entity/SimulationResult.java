package io.contexa.contexacore.domain.entity;

import io.contexa.contexacore.simulation.event.SimulationProcessingCompleteEvent.SimulationMode;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * 시뮬레이션 결과 엔티티
 *
 * 보안 시스템의 실제 처리 결과를 저장합니다.
 * 시뮬레이션 전용 테이블로 실제 운영 데이터와 격리됩니다.
 *
 * @author AI3Security
 * @since 1.0.0
 */
@Entity
@Table(name = "simulation_results",
       indexes = {
           @Index(name = "idx_simulation_attack_id", columnList = "attack_id"),
           @Index(name = "idx_simulation_processed_at", columnList = "processed_at"),
           @Index(name = "idx_simulation_mode", columnList = "simulation_mode")
       })
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SimulationResult {

    /**
     * 보안 이벤트 ID (Primary Key)
     */
    @Id
    @Column(name = "event_id", length = 50)
    private String eventId;

    /**
     * 시뮬레이션 공격 ID
     */
    @Column(name = "attack_id", length = 50, nullable = false)
    private String attackId;

    /**
     * 공격 타입
     */
    @Column(name = "attack_type", length = 50, nullable = false)
    private String attackType;

    /**
     * 대상 사용자
     */
    @Column(name = "target_user", length = 100)
    private String targetUser;

    /**
     * 공격 출발 IP
     */
    @Column(name = "source_ip", length = 45)
    private String sourceIp;

    /**
     * 위협 탐지 여부
     */
    @Column(name = "detected", nullable = false)
    private boolean detected;

    /**
     * 차단 여부
     */
    @Column(name = "blocked", nullable = false)
    private boolean blocked;

    /**
     * 위험 점수 (0.0 ~ 1.0)
     */
    @Column(name = "risk_score")
    private double riskScore;

    /**
     * 신뢰도 점수 (0.0 ~ 1.0)
     */
    @Column(name = "confidence_score")
    private double confidenceScore;

    /**
     * 처리 모드
     */
    @Column(name = "processing_mode", length = 30)
    private String processingMode;

    /**
     * 시뮬레이션 모드
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "simulation_mode", length = 20, nullable = false)
    private SimulationMode simulationMode;

    /**
     * 처리 소요 시간 (밀리초)
     */
    @Column(name = "processing_time_ms")
    private long processingTimeMs;

    /**
     * AI 분석 소요 시간 (밀리초)
     */
    @Column(name = "ai_analysis_time_ms")
    private long aiAnalysisTimeMs;

    /**
     * 처리 완료 시각
     */
    @Column(name = "processed_at", nullable = false)
    private LocalDateTime processedAt;

    /**
     * 생성 시각
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * 실행된 보안 액션 (JSON)
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "response_actions", columnDefinition = "jsonb")
    private Map<String, String> responseActions;

    /**
     * 추가 메타데이터 (JSON)
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "metadata", columnDefinition = "jsonb")
    private Map<String, Object> metadata;

    /**
     * 처리 성공 여부
     */
    @Column(name = "processing_success", nullable = false)
    private boolean processingSuccess;

    /**
     * 오류 메시지 (실패 시)
     */
    @Column(name = "error_message", length = 500)
    private String errorMessage;

    /**
     * 캠페인 ID (여러 공격이 연결된 경우)
     */
    @Column(name = "campaign_id", length = 50)
    private String campaignId;

    /**
     * 세션 ID
     */
    @Column(name = "session_id", length = 50)
    private String sessionId;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (processedAt == null) {
            processedAt = LocalDateTime.now();
        }
    }
}