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
package io.contexa.contexaidentity.security.core.dsl.option;

import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import lombok.Getter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;

import java.util.Objects;

@Getter
public abstract class AuthenticationProcessingOptions extends AbstractOptions {
    private final String loginProcessingUrl;
    private final int order;
    private final PlatformAuthenticationSuccessHandler successHandler;
    private final PlatformAuthenticationFailureHandler failureHandler;
    private final SecurityContextRepository securityContextRepository;

    protected AuthenticationProcessingOptions(AbstractAuthenticationProcessingOptionsBuilder<?, ?> builder) {
        super(builder);
        Objects.requireNonNull(builder, "Builder cannot be null");
        this.loginProcessingUrl = builder.loginProcessingUrl;
        this.order = builder.order;
        this.successHandler = builder.successHandler;
        this.failureHandler = builder.failureHandler;
        this.securityContextRepository = builder.securityContextRepository;
    }

    public abstract static class AbstractAuthenticationProcessingOptionsBuilder
            <O extends AuthenticationProcessingOptions, B extends AbstractAuthenticationProcessingOptionsBuilder<O, B>>
            extends AbstractOptions.Builder<O, B> { 

        protected String loginProcessingUrl;
        protected int order = 0;
        protected PlatformAuthenticationSuccessHandler successHandler;
        protected PlatformAuthenticationFailureHandler failureHandler;
        protected SecurityContextRepository securityContextRepository;

        public B loginProcessingUrl(String processingUrl) {
            Assert.hasText(processingUrl, "loginProcessingUrl cannot be empty or null");
            this.loginProcessingUrl = processingUrl;
            return self();
        }

        public B order(int order) {
            this.order = order;
            return self();
        }

        public B successHandler(PlatformAuthenticationSuccessHandler successHandler) {
            this.successHandler = successHandler;
            return self();
        }

        public B failureHandler(PlatformAuthenticationFailureHandler failureHandler) {
            this.failureHandler = failureHandler;
            return self();
        }

        public B securityContextRepository(SecurityContextRepository securityContextRepository) {
            this.securityContextRepository = securityContextRepository;
            return self();
        }
    }
}
