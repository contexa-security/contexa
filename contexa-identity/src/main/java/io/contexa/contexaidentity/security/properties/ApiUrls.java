package io.contexa.contexaidentity.security.properties;

import lombok.Data;

/**
 * MFA REST API 엔드포인트 URL 설정
 */
@Data
public class ApiUrls {
    /**
     * Factor 선택 API (POST)
     */
    private String selectFactor = "/api/mfa/select-factor";

    /**
     * MFA 취소 API (POST)
     */
    private String cancel = "/api/mfa/cancel";

    /**
     * MFA 상태 조회 API (GET)
     */
    private String status = "/api/mfa/status";

    /**
     * OTT 코드 재요청 API (POST)
     */
    private String requestOttCode = "/api/mfa/request-ott-code";

    /**
     * MFA 컨텍스트 조회 API (GET)
     */
    private String context = "/api/mfa/context";

    /**
     * Passkey assertion options API (POST)
     */
    private String assertionOptions = "/api/mfa/assertion/options";

    /**
     * SDK 설정 조회 API (GET) - SDK가 서버 URL 동적 로드
     */
    private String config = "/api/mfa/config";
}
