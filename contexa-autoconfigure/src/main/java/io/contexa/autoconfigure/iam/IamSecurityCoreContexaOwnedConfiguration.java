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
package io.contexa.autoconfigure.iam;

import io.contexa.contexacore.security.ContexaUserStore;
import io.contexa.autoconfigure.core.ContexaOwnBeans;
import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexaiam.security.core.CustomAuthenticationProvider;
import io.contexa.contexaiam.security.core.LoginAttemptCleanupFilter;
import io.contexa.contexaiam.security.core.LoginAttemptEventListener;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/** The sign-in policy of Contexa's own sign-in. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnOwnership(SecurityOwnershipMode.CONTEXA_OWNED)
public class IamSecurityCoreContexaOwnedConfiguration {

    @Bean(name = "contexaLoginAttemptEventListener")
    @ConditionalOnMissingBean
    public LoginAttemptEventListener loginAttemptEventListener(LoginPolicyHandler contexaLoginPolicyHandler) {
        return new LoginAttemptEventListener(contexaLoginPolicyHandler);
    }

    /**
     * Explicit registration so the filter's URL pattern, ordering, and name are deterministic
     * rather than inferred by Spring Boot's automatic Filter-bean detection. Wrapping the
     * filter in {@link FilterRegistrationBean} also prevents accidental double registration
     * (the wrapped filter is registered by this bean and skipped by the auto-detection path).
     * It comes first: a failed sign-in ends inside the security chain and reaches no filter behind it.
     */
    @Bean(name = "contexaLoginAttemptCleanupFilterRegistration")
    @ConditionalOnMissingBean(name = "contexaLoginAttemptCleanupFilterRegistration")
    public FilterRegistrationBean<LoginAttemptCleanupFilter> loginAttemptCleanupFilterRegistration() {
        FilterRegistrationBean<LoginAttemptCleanupFilter> registration =
                new FilterRegistrationBean<>(new LoginAttemptCleanupFilter());
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.setName("contexaLoginAttemptCleanupFilter");
        return registration;
    }

    /** The provider of Contexa's password sign-in: its form and MFA filters authenticate with it alone. */
    @Bean(name = "contexaCustomAuthenticationProvider")
    @ConditionalOnMissingBean
    public CustomAuthenticationProvider customAuthenticationProvider(BeanFactory beanFactory,
                                                                    LoginPolicyHandler contexaLoginPolicyHandler) {
        return new CustomAuthenticationProvider(ContexaUserStore.forSignIn(beanFactory), ContexaOwnBeans.passwordEncoder(beanFactory), contexaLoginPolicyHandler);
    }
}
