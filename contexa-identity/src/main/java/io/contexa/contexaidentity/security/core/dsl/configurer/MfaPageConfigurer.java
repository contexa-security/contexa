package io.contexa.contexaidentity.security.core.dsl.configurer;

import io.contexa.contexacommon.properties.MfaPageConfig;
import lombok.Getter;
import org.springframework.util.Assert;

@Getter
public class MfaPageConfigurer {
    
    private final MfaPageConfig config = new MfaPageConfig();

    public MfaPageConfigurer selectFactorPage(String url) {
        Assert.hasText(url, "selectFactorPage URL cannot be empty");
        config.setSelectFactorPageUrl(url);
        return this;
    }

    public MfaPageConfigurer ottPages(String requestUrl, String verifyUrl) {
        Assert.hasText(requestUrl, "OTT request page URL cannot be empty");
        Assert.hasText(verifyUrl, "OTT verify page URL cannot be empty");
        config.setOttRequestPageUrl(requestUrl);
        config.setOttVerifyPageUrl(verifyUrl);
        return this;
    }

    public MfaPageConfigurer ottRequestPage(String url) {
        Assert.hasText(url, "OTT request page URL cannot be empty");
        config.setOttRequestPageUrl(url);
        return this;
    }

    public MfaPageConfigurer ottVerifyPage(String url) {
        Assert.hasText(url, "OTT verify page URL cannot be empty");
        config.setOttVerifyPageUrl(url);
        return this;
    }

    public MfaPageConfigurer passkeyChallengePages(String url) {
        Assert.hasText(url, "Passkey challenge page URL cannot be empty");
        config.setPasskeyChallengePageUrl(url);
        return this;
    }

    public MfaPageConfigurer configurePageUrl(String url) {
        Assert.hasText(url, "Configure page URL cannot be empty");
        config.setConfigurePageUrl(url);
        return this;
    }

    public MfaPageConfigurer failurePageUrl(String url) {
        Assert.hasText(url, "Failure page URL cannot be empty");
        config.setFailurePageUrl(url);
        return this;
    }

}
