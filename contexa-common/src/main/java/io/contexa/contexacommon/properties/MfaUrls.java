package io.contexa.contexacommon.properties;

import lombok.Data;

/**
 * MFA 라이프사이클 URL 설정
 */
@Data
public class MfaUrls {
    /**
     * MFA 프로세스 시작 URL
     */
    private String initiate = "/mfa/initiate";

    /**
     * MFA 설정 UI URL
     */
    private String configure = "/mfa/configure";

    /**
     * Factor 선택 URL (GET: 페이지 표시, POST: Factor 선택 처리)
     * MfaContinuationFilter에서 Content-Type에 따라 HTML/JSON 응답
     */
    private String selectFactor = "/mfa/select-factor";

    /**
     * MFA 성공 리다이렉트 URL
     *
     * <p>
     * 주의: Primary Auth의 loginSuccess와 동일한 URL을 사용하면 중복 검증 실패합니다.
     * 하지만 기능적으로 동일한 목적지이므로, 실제로는 Primary loginSuccess URL을 참조해야 합니다.
     * 검증 로직에서 이 경우는 허용되어야 합니다.
     * </p>
     */
    private String success = "/home";

    /**
     * MFA 실패 페이지 URL
     */
    private String failure = "/mfa/failure";

    /**
     * MFA 취소 URL (POST)
     * MfaContinuationFilter에서 처리
     */
    private String cancel = "/mfa/cancel";

    /**
     * MFA 취소 리다이렉트 URL (로그인 페이지)
     */
    private String cancelRedirect = "/loginForm";

    /**
     * MFA 상태 조회 URL (GET)
     * MfaContinuationFilter에서 처리
     */
    private String status = "/mfa/status";

    /**
     * MFA Context 조회 URL (GET)
     * SDK에서 FactorContext 정보를 동적으로 가져오기 위해 사용
     */
    private String context = "/api/mfa/context";

    /**
     * OTT 코드 재전송 요청 URL (POST)
     * MfaContinuationFilter에서 처리
     */
    private String requestOttCode = "/mfa/request-ott-code";

    /**
     * SDK 설정 조회 URL (GET)
     * SDK가 런타임에 모든 엔드포인트 URL을 로드
     *
     * 참고: 이 URL만 /api 경로 유지 (설정 조회 전용)
     */
    private String config = "/api/mfa/config";
}
