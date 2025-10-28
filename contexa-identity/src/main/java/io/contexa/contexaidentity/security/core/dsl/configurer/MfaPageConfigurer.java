package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexaidentity.security.properties.MfaPageConfig;
import lombok.Getter;
import org.springframework.util.Assert;

/**
 * MFA Page Configurer
 *
 * MFA 커스텀 페이지 URL을 설정하는 DSL Builder 클래스.
 * Fluent API 패턴을 사용하여 직관적인 설정을 제공함.
 *
 * 사용 예시:
 * <pre>
 * .mfa(mfa -> mfa
 *     .mfaPage(page -> page
 *         .selectFactorPage("/custom/mfa/select")
 *         .ottPages("/custom/mfa/ott-request", "/custom/mfa/ott-verify")
 *         .passkeyChallengePages("/custom/mfa/passkey")
 *         .configurePageUrl("/custom/mfa/configure")
 *         .failurePageUrl("/custom/mfa/failure")
 *     )
 * )
 * </pre>
 *
 * @see MfaPageConfig
 * @see io.contexa.contexaidentity.security.filter.DefaultMfaPageGeneratingFilter
 */
@Getter
public class MfaPageConfigurer {
    /**
     * -- GETTER --
     *  빌드된 MfaPageConfig 반환 (내부 사용)
     *
     * @return MfaPageConfig
     */
    private final MfaPageConfig config = new MfaPageConfig();

    /**
     * 팩터 선택 페이지 커스텀 URL 설정
     *
     * @param url 커스텀 컨트롤러 URL (예: "/custom/mfa/select")
     * @return this
     */
    public MfaPageConfigurer selectFactorPage(String url) {
        Assert.hasText(url, "selectFactorPage URL cannot be empty");
        config.setSelectFactorPageUrl(url);
        return this;
    }

    /**
     * OTT 페이지들 일괄 설정
     *
     * @param requestUrl OTT 코드 요청 페이지 URL
     * @param verifyUrl OTT 코드 검증 페이지 URL
     * @return this
     */
    public MfaPageConfigurer ottPages(String requestUrl, String verifyUrl) {
        Assert.hasText(requestUrl, "OTT request page URL cannot be empty");
        Assert.hasText(verifyUrl, "OTT verify page URL cannot be empty");
        config.setOttRequestPageUrl(requestUrl);
        config.setOttVerifyPageUrl(verifyUrl);
        return this;
    }

    /**
     * OTT 코드 요청 페이지 커스텀 URL 설정
     *
     * @param url 커스텀 컨트롤러 URL (예: "/custom/mfa/ott-request")
     * @return this
     */
    public MfaPageConfigurer ottRequestPage(String url) {
        Assert.hasText(url, "OTT request page URL cannot be empty");
        config.setOttRequestPageUrl(url);
        return this;
    }

    /**
     * OTT 코드 검증 페이지 커스텀 URL 설정
     *
     * @param url 커스텀 컨트롤러 URL (예: "/custom/mfa/ott-verify")
     * @return this
     */
    public MfaPageConfigurer ottVerifyPage(String url) {
        Assert.hasText(url, "OTT verify page URL cannot be empty");
        config.setOttVerifyPageUrl(url);
        return this;
    }

    /**
     * Passkey 인증 페이지 커스텀 URL 설정
     *
     * @param url 커스텀 컨트롤러 URL (예: "/custom/mfa/passkey")
     * @return this
     */
    public MfaPageConfigurer passkeyChallengePages(String url) {
        Assert.hasText(url, "Passkey challenge page URL cannot be empty");
        config.setPasskeyChallengePageUrl(url);
        return this;
    }

    /**
     * MFA 초기 설정 페이지 커스텀 URL 설정
     *
     * @param url 커스텀 컨트롤러 URL (예: "/custom/mfa/configure")
     * @return this
     */
    public MfaPageConfigurer configurePageUrl(String url) {
        Assert.hasText(url, "Configure page URL cannot be empty");
        config.setConfigurePageUrl(url);
        return this;
    }

    /**
     * MFA 실패 페이지 커스텀 URL 설정
     *
     * @param url 커스텀 컨트롤러 URL (예: "/custom/mfa/failure")
     * @return this
     */
    public MfaPageConfigurer failurePageUrl(String url) {
        Assert.hasText(url, "Failure page URL cannot be empty");
        config.setFailurePageUrl(url);
        return this;
    }

}
