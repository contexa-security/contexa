package io.contexa.contexacommon.properties;

import lombok.Data;
import org.springframework.util.StringUtils;


@Data
public class MfaPageConfig {
    
    private String selectFactorPageUrl;

    
    private String ottRequestPageUrl;

    
    private String ottVerifyPageUrl;

    
    private String passkeyChallengePageUrl;

    
    private String configurePageUrl;

    
    private String failurePageUrl;

    
    public boolean hasCustomSelectFactorPage() {
        return StringUtils.hasText(selectFactorPageUrl);
    }

    
    public boolean hasCustomOttRequestPage() {
        return StringUtils.hasText(ottRequestPageUrl);
    }

    
    public boolean hasCustomOttVerifyPage() {
        return StringUtils.hasText(ottVerifyPageUrl);
    }

    
    public boolean hasCustomOttPages() {
        return hasCustomOttRequestPage() && hasCustomOttVerifyPage();
    }

    
    public boolean hasCustomPasskeyPage() {
        return StringUtils.hasText(passkeyChallengePageUrl);
    }

    
    public boolean hasCustomConfigurePage() {
        return StringUtils.hasText(configurePageUrl);
    }

    
    public boolean hasCustomFailurePage() {
        return StringUtils.hasText(failurePageUrl);
    }

    
    public boolean hasAnyCustomPage() {
        return hasCustomSelectFactorPage()
                || hasCustomOttPages()
                || hasCustomPasskeyPage()
                || hasCustomConfigurePage()
                || hasCustomFailurePage();
    }
}
