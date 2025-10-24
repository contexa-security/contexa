package io.contexa.contexaidentity.security.core.dsl.option;

import io.contexa.contexaidentity.security.core.asep.dsl.FormAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import lombok.Getter;
import org.springframework.util.Assert;

import java.util.Objects;

@Getter
public final class FormOptions extends AuthenticationProcessingOptions {

    private final String loginPage;
    private final String usernameParameter;
    private final String passwordParameter;
    private final String defaultSuccessUrl;
    private final String failureUrl;
    private final boolean permitAll;
    private final boolean alwaysUseDefaultSuccessUrl;
    private final SafeHttpFormLoginCustomizer rawFormLoginCustomizer;
    private final FormAsepAttributes asepAttributes;

    private FormOptions(Builder builder) {
        super(builder);
        this.loginPage = builder.loginPage;
        this.usernameParameter = Objects.requireNonNull(builder.usernameParameter, "usernameParameter cannot be null");
        this.passwordParameter = Objects.requireNonNull(builder.passwordParameter, "passwordParameter cannot be null");
        this.defaultSuccessUrl = builder.defaultSuccessUrl;
        this.failureUrl = builder.failureUrl;
        this.permitAll = builder.permitAll;
        this.alwaysUseDefaultSuccessUrl = builder.alwaysUseDefaultSuccessUrl;
        this.rawFormLoginCustomizer = builder.rawFormLoginCustomizer;
        this.asepAttributes = builder.asepAttributes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<FormOptions, Builder> {
        private String loginPage = "/loginForm";
        private String usernameParameter = "username";
        private String passwordParameter = "password";
        private String defaultSuccessUrl = "/";
        private String failureUrl = "/loginForm?error";
        private boolean permitAll = false;
        private boolean alwaysUseDefaultSuccessUrl = false;
        private SafeHttpFormLoginCustomizer rawFormLoginCustomizer;
        private FormAsepAttributes asepAttributes;

        public Builder() {
            // super(); // 부모 생성자 명시적 호출 불필요 (기본 생성자)
            super.loginProcessingUrl("/login"); // AuthenticationProcessingOptions의 loginProcessingUrl 기본값 설정
            super.order(100); // 예시 기본 순서
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder loginPage(String loginPage) {
            Assert.hasText(loginPage, "loginPage cannot be empty or null");
            this.loginPage = loginPage;
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
            this.alwaysUseDefaultSuccessUrl = false;
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

        public Builder permitAll(boolean permitAll) {
            this.permitAll = permitAll;
            return this;
        }
        public Builder permitAll() {
            return permitAll(true);
        }

        public Builder alwaysUseDefaultSuccessUrl(boolean alwaysUseDefaultSuccessUrl) {
            this.alwaysUseDefaultSuccessUrl = alwaysUseDefaultSuccessUrl;
            return this;
        }

        public Builder rawFormLoginCustomizer(SafeHttpFormLoginCustomizer rawFormLoginCustomizer) {
            this.rawFormLoginCustomizer = rawFormLoginCustomizer;
            return this;
        }

        public Builder asepAttributes(FormAsepAttributes attributes) {
            this.asepAttributes = attributes;
            return this;
        }

        @Override
        public FormOptions build() {
            Assert.hasText(loginProcessingUrl, "loginProcessingUrl must be set for FormOptions");
            return new FormOptions(this);
        }
    }
}