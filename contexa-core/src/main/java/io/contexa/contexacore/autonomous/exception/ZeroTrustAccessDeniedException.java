package io.contexa.contexacore.autonomous.exception;

import org.springframework.security.access.AccessDeniedException;

/**
 * Zero Trust 보안 아키텍처 통합 예외 클래스
 *
 * URL Security와 Method Security에서 일관된 예외 처리를 위해 사용한다.
 * LLM action 기반 차단 시 발생하며, action 유형에 따른 HTTP 상태 코드 매핑을 지원한다.
 *
 * action별 HTTP 상태 코드:
 * - BLOCK: 403 Forbidden
 * - CHALLENGE: 401 Unauthorized (MFA 필요)
 * - INVESTIGATE/ESCALATE: 423 Locked (검토 대기)
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
public class ZeroTrustAccessDeniedException extends AccessDeniedException {

    private static final long serialVersionUID = 1L;

    /**
     * LLM이 결정한 action (BLOCK, CHALLENGE, INVESTIGATE, ESCALATE)
     */
    private final String action;

    /**
     * 접근 시도한 리소스 식별자
     */
    private final String resourceId;

    /**
     * HCAD 위험도 점수 (0.0 ~ 1.0)
     */
    private final double riskScore;

    /**
     * 차단 사유
     */
    private final String reason;

    /**
     * 분석 타임아웃 여부
     */
    private final boolean analysisTimeout;

    /**
     * Zero Trust 접근 거부 예외 생성
     *
     * @param action LLM action
     * @param resourceId 리소스 식별자
     * @param riskScore 위험도 점수
     * @param reason 차단 사유
     */
    public ZeroTrustAccessDeniedException(String action, String resourceId,
                                          double riskScore, String reason) {
        super(formatMessage(action, reason));
        this.action = action;
        this.resourceId = resourceId;
        this.riskScore = riskScore;
        this.reason = reason;
        this.analysisTimeout = false;
    }

    /**
     * 분석 타임아웃 포함 예외 생성
     *
     * @param action LLM action
     * @param resourceId 리소스 식별자
     * @param riskScore 위험도 점수
     * @param reason 차단 사유
     * @param analysisTimeout 분석 타임아웃 여부
     */
    public ZeroTrustAccessDeniedException(String action, String resourceId,
                                          double riskScore, String reason,
                                          boolean analysisTimeout) {
        super(formatMessage(action, reason));
        this.action = action;
        this.resourceId = resourceId;
        this.riskScore = riskScore;
        this.reason = reason;
        this.analysisTimeout = analysisTimeout;
    }

    /**
     * 분석 타임아웃 전용 예외 생성
     *
     * @param resourceId 리소스 식별자
     * @param timeoutMs 타임아웃 밀리초
     * @return 타임아웃 예외
     */
    public static ZeroTrustAccessDeniedException analysisTimeout(String resourceId, long timeoutMs) {
        return new ZeroTrustAccessDeniedException(
            "PENDING_ANALYSIS",
            resourceId,
            0.5,
            String.format("Security analysis timeout after %dms", timeoutMs),
            true
        );
    }

    /**
     * 분석 미완료 예외 생성
     *
     * @param resourceId 리소스 식별자
     * @return 분석 미완료 예외
     */
    public static ZeroTrustAccessDeniedException analysisRequired(String resourceId) {
        return new ZeroTrustAccessDeniedException(
            "PENDING_ANALYSIS",
            resourceId,
            0.5,
            "Security analysis required but not completed"
        );
    }

    /**
     * 차단 예외 생성
     *
     * @param resourceId 리소스 식별자
     * @param riskScore 위험도 점수
     * @return 차단 예외
     */
    public static ZeroTrustAccessDeniedException blocked(String resourceId, double riskScore) {
        return new ZeroTrustAccessDeniedException(
            "BLOCK",
            resourceId,
            riskScore,
            "Access blocked by AI security analysis"
        );
    }

    /**
     * MFA 요구 예외 생성
     *
     * @param resourceId 리소스 식별자
     * @param riskScore 위험도 점수
     * @return MFA 요구 예외
     */
    public static ZeroTrustAccessDeniedException challengeRequired(String resourceId, double riskScore) {
        return new ZeroTrustAccessDeniedException(
            "CHALLENGE",
            resourceId,
            riskScore,
            "Additional authentication required"
        );
    }

    /**
     * 검토 대기 예외 생성
     *
     * @param resourceId 리소스 식별자
     * @param riskScore 위험도 점수
     * @return 검토 대기 예외
     */
    public static ZeroTrustAccessDeniedException pendingReview(String resourceId, double riskScore) {
        return new ZeroTrustAccessDeniedException(
            "INVESTIGATE",
            resourceId,
            riskScore,
            "Access pending security review"
        );
    }

    private static String formatMessage(String action, String reason) {
        return String.format("Zero Trust: %s - %s", action, reason);
    }

    /**
     * action에 따른 HTTP 상태 코드 반환
     *
     * @return HTTP 상태 코드
     */
    public int getHttpStatus() {
        if (action == null) {
            return 403;
        }
        return switch (action.toUpperCase()) {
            case "BLOCK" -> 403;           // Forbidden
            case "CHALLENGE" -> 401;       // Unauthorized (MFA 필요)
            case "INVESTIGATE", "ESCALATE" -> 423; // Locked (검토 대기)
            case "PENDING_ANALYSIS" -> analysisTimeout ? 408 : 503; // Request Timeout / Service Unavailable
            default -> 403;
        };
    }

    /**
     * 에러 코드 반환
     *
     * @return 에러 코드 (예: ZERO_TRUST_BLOCK)
     */
    public String getErrorCode() {
        return "ZERO_TRUST_" + (action != null ? action.toUpperCase() : "UNKNOWN");
    }

    // Getters

    public String getAction() {
        return action;
    }

    public String getResourceId() {
        return resourceId;
    }

    public double getRiskScore() {
        return riskScore;
    }

    public String getReason() {
        return reason;
    }

    public boolean isAnalysisTimeout() {
        return analysisTimeout;
    }
}
