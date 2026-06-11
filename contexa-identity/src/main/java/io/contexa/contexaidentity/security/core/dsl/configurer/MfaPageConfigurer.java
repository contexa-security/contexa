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
