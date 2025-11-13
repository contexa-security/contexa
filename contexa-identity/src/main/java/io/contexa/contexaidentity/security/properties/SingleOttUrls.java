package io.contexa.contexaidentity.security.properties;

import lombok.Data;

/**
 * 단일 OTT(One-Time Token) 인증 URL 설정 (MFA 없는 독립 인증)
 */
@Data
public class SingleOttUrls {
    /**
     * OTT 이메일 요청 페이지 (GET)
     */
    private String requestEmail = "/login/ott";

    /**
     * OTT 코드 생성 URL (POST)
     * Spring Security GenerateOneTimeTokenFilter 기본값
     */
    private String codeGeneration = "/ott/generate";

    /**
     * OTT 코드 전송 완료 페이지
     */
    private String codeSent = "/login/ott/sent";

    /**
     * OTT 코드 입력 챌린지 페이지 (GET)
     */
    private String challenge = "/login/ott/verify";

    /**
     * OTT 코드 검증 처리 URL (POST)
     * Spring Security OneTimeTokenLogin 필터가 처리
     */
    private String loginProcessing = "/login/ott";

    /**
     * OTT 검증 실패 리다이렉트 URL
     */
    private String loginFailure = "/login/ott?error";
}
