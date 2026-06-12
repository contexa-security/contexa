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

import io.contexa.contexaidentity.security.core.asep.dsl.RestAsepAttributes;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import java.util.Objects;
import lombok.Getter;
import org.springframework.context.ApplicationContext;
import org.springframework.util.Assert;

@Getter
public final class RestOptions extends AuthenticationProcessingOptions {

    private final String usernameParameter;
    private final String passwordParameter;
    private final String defaultSuccessUrl;
    private final String failureUrl;
    private final boolean alwaysUseDefaultSuccessUrl;
    private final RestAsepAttributes asepAttributes;

    private RestOptions(Builder builder) {
        super(builder);
        this.usernameParameter = Objects.requireNonNull(builder.usernameParameter, "usernameParameter cannot be null");
        this.passwordParameter = Objects.requireNonNull(builder.passwordParameter, "passwordParameter cannot be null");
        this.defaultSuccessUrl = builder.defaultSuccessUrl;
        this.failureUrl = builder.failureUrl;
        this.alwaysUseDefaultSuccessUrl = builder.alwaysUseDefaultSuccessUrl;
        this.asepAttributes = builder.asepAttributes;
    }

    public static Builder builder(ApplicationContext applicationContext) {
        return new Builder(applicationContext, false);
    }

    public static Builder builderForMfa(ApplicationContext applicationContext) {
        return new Builder(applicationContext, true);
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<RestOptions, Builder> {
        private String usernameParameter = "username";
        private String passwordParameter = "password";
        private String defaultSuccessUrl;
        private String failureUrl;
        private boolean alwaysUseDefaultSuccessUrl = false;
        private RestAsepAttributes asepAttributes; 

        public Builder(ApplicationContext applicationContext) {
            this(applicationContext, false);
        }

        private Builder(ApplicationContext applicationContext, boolean isMfaMode) {
            Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null for RestOptions.Builder");
            AuthUrlProvider urlProvider = applicationContext.getBean(AuthUrlProvider.class);

            if (isMfaMode) {
                super.loginProcessingUrl(urlProvider.getPrimaryRestLoginProcessing());
            } else {
                super.loginProcessingUrl(urlProvider.getSingleRestLoginProcessing());
            }
            super.order(200);
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder usernameParameter(String usernameParameter) {
            Assert.hasText(usernameParameter, "usernameParameter cannot be empty or null");
            this.usernameParameter = usernameParameter;
            return this;
        }

        public Builder passwordParameter(String passwordParameter) {
            Assert.hasText(passwordParameter, "passwordParameter cannot be empty or null");
            this.passwordParameter = passwordParameter;
            return this;
        }

        public Builder defaultSuccessUrl(String defaultSuccessUrl) {
            this.defaultSuccessUrl = defaultSuccessUrl;
            return this;
        }
        public Builder defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
            this.defaultSuccessUrl = defaultSuccessUrl;
            this.alwaysUseDefaultSuccessUrl = alwaysUse;
            return this;
        }

        public Builder failureUrl(String failureUrl) {
            this.failureUrl = failureUrl;
            return this;
        }

        public Builder asepAttributes(RestAsepAttributes attributes) { 
            this.asepAttributes = attributes;
            return this;
        }

        @Override
        public RestOptions build() {
            Assert.hasText(loginProcessingUrl, "loginProcessingUrl must be set for RestOptions");
            Assert.hasText(usernameParameter, "usernameParameter must be set for RestOptions");
            Assert.hasText(passwordParameter, "passwordParameter must be set for RestOptions");
            return new RestOptions(this);
        }
    }
}