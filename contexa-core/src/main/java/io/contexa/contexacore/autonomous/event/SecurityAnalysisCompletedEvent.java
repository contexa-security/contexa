package io.contexa.contexacore.autonomous.event;

import lombok.Builder;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;

/**
 * LLM 보안 분석 완료 이벤트
 *
 * ColdPathEventProcessor에서 분석 완료 시 발행되어
 * ZeroTrustResponseInterceptor에서 실시간 응답 차단에 사용된다.
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Getter
public class SecurityAnalysisCompletedEvent extends ApplicationEvent {

    private static final long serialVersionUID = 1L;

    /**
     * 요청 식별자 (ZeroTrustResponseFilter에서 생성)
     */
    private final String requestId;

    /**
     * 사용자 ID
     */
    private final String userId;

    /**
     * LLM이 결정한 action
     */
    private final String action;

    /**
     * 위험도 점수 (0.0 ~ 1.0)
     */
    private final double riskScore;

    /**
     * 신뢰도 (0.0 ~ 1.0)
     */
    private final double confidence;

    /**
     * 분석 완료 시각
     */
    private final Instant completedAt;

    /**
     * 분석 소요 시간 (밀리초)
     */
    private final long processingTimeMs;

    /**
     * 위협 유형 (옵션)
     */
    private final String threatType;

    /**
     * 위협 증거 (옵션)
     */
    private final String threatEvidence;

    @Builder
    public SecurityAnalysisCompletedEvent(Object source,
                                          String requestId,
                                          String userId,
                                          String action,
                                          double riskScore,
                                          double confidence,
                                          Instant completedAt,
                                          long processingTimeMs,
                                          String threatType,
                                          String threatEvidence) {
        super(source);
        this.requestId = requestId;
        this.userId = userId;
        this.action = action;
        this.riskScore = riskScore;
        this.confidence = confidence;
        this.completedAt = completedAt != null ? completedAt : Instant.now();
        this.processingTimeMs = processingTimeMs;
        this.threatType = threatType;
        this.threatEvidence = threatEvidence;
    }

    /**
     * 차단 필요 여부 확인
     *
     * @return BLOCK action이면 true
     */
    public boolean requiresBlocking() {
        return "BLOCK".equalsIgnoreCase(action);
    }

    /**
     * 고위험 여부 확인
     *
     * @return 위험도 점수가 0.7 이상이면 true
     */
    public boolean isHighRisk() {
        return riskScore >= 0.7;
    }

    @Override
    public String toString() {
        return String.format("SecurityAnalysisCompletedEvent[requestId=%s, userId=%s, action=%s, riskScore=%.2f]",
            requestId, userId, action, riskScore);
    }
}
