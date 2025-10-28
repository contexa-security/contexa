package io.contexa.contexacore.autonomous.event.domain;

import io.contexa.contexacore.autonomous.event.decision.EventTier;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.springframework.security.core.Authentication;

import java.time.LocalDateTime;

/**
 * HTTP 요청 이벤트
 *
 * SecurityEventPublishingFilter에서 발행하여
 * ZeroTrustEventListener가 수신하는 이벤트
 *
 * 통합 AI 분석 결과 포함:
 * - eventTier: Risk Score 기반 위험도 등급
 * - riskScore: 통합 위험도 점수
 * - trustScore: 인증 사용자 신뢰 점수 (인증 사용자 전용)
 * - ipThreatScore: IP 위협 점수 (익명 사용자 전용)
 *
 * ApplicationEvent를 상속하지 않는 순수 DTO입니다.
 * ApplicationEventPublisher.publishEvent(Object)로 발행 가능합니다.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class HttpRequestEvent {

    private String eventId;
    private LocalDateTime eventTimestamp;
    private String userId;
    private String sourceIp;
    private String requestUri;
    private String httpMethod;
    private int statusCode;
    private Double hcadSimilarityScore;
    private Authentication authentication;

    // HCAD 피드백 루프 완전 통합 (v2.0)
    private Boolean hcadIsAnomaly;         // 학습된 임계값 기반 이상 탐지 판정
    private Double hcadAnomalyScore;       // 이상 점수 (1.0 - similarity)
    private Double hcadThreshold;          // 사용된 학습 임계값

    // 통합 AI 분석 결과
    private boolean isAnonymous;
    private EventTier eventTier;          // Risk Score 기반
    private Double riskScore;              // 통합 위험도 점수
    private Double trustScore;             // 인증 사용자 신뢰 점수
    private Double ipThreatScore;          // 익명 사용자 IP 위협 점수
}
