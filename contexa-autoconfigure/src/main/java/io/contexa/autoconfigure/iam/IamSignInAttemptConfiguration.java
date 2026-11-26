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

import io.contexa.autoconfigure.core.ContexaAccountRequests;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexaiam.security.core.LoginAttemptCleanupFilter;
import io.contexa.contexaiam.security.core.LoginAttemptEventListener;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;

/**
 * The sign-in attempt policy, in every way of running Contexa (M4 of docs/agent/운영모드-정상화-구현계획.md). Its listener hears
 * every sign-in event of the application as well, and tells Contexa's sign-ins apart ({@link ContexaAccountRequests}): a
 * sign-in of an account of Contexa's goes to the account policy, and a failed sign-in of the application's own users is kept
 * for the decisions and counted against its address without touching any account of Contexa's.
 */
@Configuration(proxyBeanMethods = false)
public class IamSignInAttemptConfiguration {

    @Bean(name = "contexaLoginAttemptEventListener")
    @ConditionalOnMissingBean
    public LoginAttemptEventListener loginAttemptEventListener(LoginPolicyHandler contexaLoginPolicyHandler,
                                                               Environment environment) {
        return new LoginAttemptEventListener(contexaLoginPolicyHandler, ContexaAccountRequests.of(environment));
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

}
