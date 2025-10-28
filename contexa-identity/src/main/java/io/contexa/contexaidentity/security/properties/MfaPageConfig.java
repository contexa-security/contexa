package io.contexa.contexaidentity.security.properties;

import lombok.Data;
import org.springframework.util.StringUtils;

/**
 * MFA Page Configuration
 *
 * 커스텀 MFA 페이지 URL 설정을 저장하는 설정 클래스.
 * DefaultMfaPageGeneratingFilter에서 커스텀 페이지 사용 여부를 판단하는데 사용됨.
 *
 * 사용 예시:
 * <pre>
 * .mfa(mfa -> mfa
 *     .mfaPage(page -> page
 *         .selectFactorPage("/custom/mfa/select")
 *         .ottPages("/custom/mfa/ott-request", "/custom/mfa/ott-verify")
 *         .passkeyChallengePages("/custom/mfa/passkey")
 *     )
 * )
 * </pre>
 */
@Data
public class MfaPageConfig {
    /**
     * 팩터 선택 페이지 커스텀 URL
     */
    private String selectFactorPageUrl;

    /**
     * OTT 코드 요청 페이지 커스텀 URL
     */
    private String ottRequestPageUrl;

    /**
     * OTT 코드 검증 페이지 커스텀 URL
     */
    private String ottVerifyPageUrl;

    /**
     * Passkey 인증 페이지 커스텀 URL
     */
    private String passkeyChallengePageUrl;

    /**
     * MFA 초기 설정 페이지 커스텀 URL
     */
    private String configurePageUrl;

    /**
     * MFA 실패 페이지 커스텀 URL
     */
    private String failurePageUrl;

    /**
     * 커스텀 팩터 선택 페이지가 설정되었는지 확인
     */
    public boolean hasCustomSelectFactorPage() {
        return StringUtils.hasText(selectFactorPageUrl);
    }

    /**
     * 커스텀 OTT 요청 페이지가 설정되었는지 확인
     */
    public boolean hasCustomOttRequestPage() {
        return StringUtils.hasText(ottRequestPageUrl);
    }

    /**
     * 커스텀 OTT 검증 페이지가 설정되었는지 확인
     */
    public boolean hasCustomOttVerifyPage() {
        return StringUtils.hasText(ottVerifyPageUrl);
    }

    /**
     * 커스텀 OTT 페이지들이 모두 설정되었는지 확인
     */
    public boolean hasCustomOttPages() {
        return hasCustomOttRequestPage() && hasCustomOttVerifyPage();
    }

    /**
     * 커스텀 Passkey 페이지가 설정되었는지 확인
     */
    public boolean hasCustomPasskeyPage() {
        return StringUtils.hasText(passkeyChallengePageUrl);
    }

    /**
     * 커스텀 설정 페이지가 설정되었는지 확인
     */
    public boolean hasCustomConfigurePage() {
        return StringUtils.hasText(configurePageUrl);
    }

    /**
     * 커스텀 실패 페이지가 설정되었는지 확인
     */
    public boolean hasCustomFailurePage() {
        return StringUtils.hasText(failurePageUrl);
    }

    /**
     * 어떤 커스텀 페이지라도 설정되었는지 확인
     */
    public boolean hasAnyCustomPage() {
        return hasCustomSelectFactorPage()
                || hasCustomOttPages()
                || hasCustomPasskeyPage()
                || hasCustomConfigurePage()
                || hasCustomFailurePage();
    }
}
