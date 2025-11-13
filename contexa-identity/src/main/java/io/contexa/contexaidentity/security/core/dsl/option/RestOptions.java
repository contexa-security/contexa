package io.contexa.contexaidentity.security.core.dsl.option;

import io.contexa.contexaidentity.security.core.asep.dsl.RestAsepAttributes;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import lombok.Getter;
import org.springframework.context.ApplicationContext;
import org.springframework.util.Assert;

import java.util.Objects;

@Getter
public final class RestOptions extends AuthenticationProcessingOptions {

    private final String usernameParameter;
    private final String passwordParameter;
    private final RestAsepAttributes asepAttributes; // 추가

    private RestOptions(Builder builder) {
        super(builder);
        this.usernameParameter = Objects.requireNonNull(builder.usernameParameter, "usernameParameter cannot be null");
        this.passwordParameter = Objects.requireNonNull(builder.passwordParameter, "passwordParameter cannot be null");
        this.asepAttributes = builder.asepAttributes; // 추가
    }

    /**
     * 단일 인증용 Builder 생성 (기본)
     */
    public static Builder builder(org.springframework.context.ApplicationContext applicationContext) {
        return new Builder(applicationContext, false);
    }

    /**
     * MFA 1차 인증용 Builder 생성
     */
    public static Builder builderForMfa(org.springframework.context.ApplicationContext applicationContext) {
        return new Builder(applicationContext, true);
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<RestOptions, Builder> {
        private String usernameParameter = "username";
        private String passwordParameter = "password";
        private RestAsepAttributes asepAttributes; // 추가

        /**
         * 단일 인증용 생성자 (기본 - 하위 호환성)
         */
        public Builder(org.springframework.context.ApplicationContext applicationContext) {
            this(applicationContext, false);
        }

        /**
         * 단일/MFA 구분 생성자
         * @param applicationContext ApplicationContext
         * @param isMfaMode true: MFA 1차 인증, false: 단일 인증
         */
        private Builder(ApplicationContext applicationContext, boolean isMfaMode) {
            Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null for RestOptions.Builder");

            // AuthUrlProvider를 통해 동적으로 URL 가져오기
            AuthUrlProvider urlProvider = applicationContext.getBean(AuthUrlProvider.class);

            if (isMfaMode) {
                // MFA 1차 인증 URL
                super.loginProcessingUrl(urlProvider.getPrimaryRestLoginProcessing());
            } else {
                // 단일 인증 URL
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

        public Builder asepAttributes(RestAsepAttributes attributes) { // 추가
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