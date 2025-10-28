package io.contexa.contexaidentity.security.properties;

import lombok.Data;

/**
 * OTT(One-Time Token) Factor URL 설정
 */
@Data
public class OttUrls {
    // === MFA Flow URLs ===

    /**
     * OTT 코드 요청 UI 페이지 (이메일 입력)
     */
    private String requestCodeUi = "/mfa/ott/request-code-ui";

    /**
     * OTT 코드 생성 URL (POST)
     */
    private String codeGeneration = "/mfa/ott/generate-code";

    /**
     * OTT 코드 전송 완료 페이지
     */
    private String codeSent = "/mfa/ott/code-sent";

    /**
     * OTT 코드 입력 챌린지 UI
     */
    private String challengeUi = "/mfa/challenge/ott";

    /**
     * OTT 코드 검증 처리 URL (POST) - Filter가 처리
     */
    private String loginProcessing = "/login/mfa-ott";

    /**
     * OTT 검증 실패 기본 URL
     */
    private String defaultFailure = "/mfa/challenge/ott?error=true";

    // === Single OTT Flow URLs (Standalone) ===

    /**
     * 단일 OTT 이메일 요청 페이지
     */
    private String singleOttRequestEmail = "/loginOtt";

    /**
     * 단일 OTT 코드 생성 URL
     */
    private String singleOttCodeGeneration = "/login/ott/generate";

    /**
     * 단일 OTT 챌린지 페이지
     */
    private String singleOttChallenge = "/loginOttVerifyCode";

    /**
     * 단일 OTT 코드 전송 완료 페이지
     */
    private String singleOttSent = "/ott/sent";
}
