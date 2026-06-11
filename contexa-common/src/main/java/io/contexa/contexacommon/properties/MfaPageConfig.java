/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacommon.properties;

import lombok.Data;
import org.springframework.util.StringUtils;


@Data
public class MfaPageConfig {
    
    private String primaryLoginPageUrl;
    private String selectFactorPageUrl;

    
    private String ottRequestPageUrl;

    
    private String ottVerifyPageUrl;

    
    private String passkeyChallengePageUrl;

    
    private String configurePageUrl;

    
    private String failurePageUrl;

    
    public boolean hasCustomPrimaryLoginPage() {
        return StringUtils.hasText(primaryLoginPageUrl);
    }

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
