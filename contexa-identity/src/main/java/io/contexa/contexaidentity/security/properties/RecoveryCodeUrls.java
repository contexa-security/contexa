package io.contexa.contexaidentity.security.properties;

import lombok.Data;

/**
 * Recovery Code Factor URL 설정
 */
@Data
public class RecoveryCodeUrls {
    /**
     * Recovery code 검증 처리 URL (POST)
     */
    private String loginProcessing = "/login/recovery/verify";

    /**
     * Recovery code 챌린지 UI
     */
    private String challengeUi = "/mfa/challenge/recovery";
}
