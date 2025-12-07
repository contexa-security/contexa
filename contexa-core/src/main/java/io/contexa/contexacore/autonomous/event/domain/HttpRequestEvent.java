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
    private String userAgent;  // User-Agent 헤더 (봇/정상 사용자 구별용)
    private Authentication authentication;

    // HCAD AI Native (v3.0)
    private Boolean hcadIsAnomaly;         // AI Native: LLM이 직접 결정한 이상 여부
    private Double hcadAnomalyScore;       // AI Native: LLM이 결정한 위험도 점수 (riskScore)
    private String hcadAction;             // AI Native: LLM이 결정한 action (ALLOW/BLOCK/ESCALATE/MONITOR/INVESTIGATE)

    // 통합 AI 분석 결과
    private boolean isAnonymous;
    private EventTier eventTier;          // Risk Score 기반
    private Double riskScore;              // 통합 위험도 점수
    private Double trustScore;             // 인증 사용자 신뢰 점수
    private Double ipThreatScore;          // 익명 사용자 IP 위협 점수

    // Phase 9: 세션/사용자 컨텍스트 정보 (Layer1 프롬프트 강화용)
    private Boolean isNewSession;          // 신규 세션 여부
    private Boolean isNewUser;             // 신규 사용자 여부 (이전 HCAD 분석 기록 없음)
    private Boolean isNewDevice;           // 신규 디바이스 여부
    private Integer recentRequestCount;    // 최근 5분간 요청 수
}
