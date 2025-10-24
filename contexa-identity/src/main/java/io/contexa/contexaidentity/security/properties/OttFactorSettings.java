package io.contexa.contexaidentity.security.properties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OttFactorSettings {
    private String requestCodeUiUrl = "/mfa/ott/request-code-ui";
    private String codeGenerationUrl = "/mfa/ott/generate-code";
    private String codeSentUrl = "/mfa/ott/code-sent"; // 코드 발송 안내 UI (선택적)
    private String challengeUrl = "/mfa/challenge/ott"; // 코드 입력 UI (GET)
    private String loginProcessingUrl = "/login/mfa-ott"; // 코드 검증 처리 URL (POST)
    private String defaultFailureUrl = "/mfa/challenge/ott?error=true";
    private int tokenValiditySeconds = 300; // 단일 OTT 용으로도 사용될 수 있음

    // 단일 OTT 관련 URL들
    private String singleOttRequestEmailUrl = "/loginOtt";
    private String singleOttCodeGenerationUrl = "/login/ott/generate";
    private String singleOttChallengeUrl = "/loginOttVerifyCode";
}
