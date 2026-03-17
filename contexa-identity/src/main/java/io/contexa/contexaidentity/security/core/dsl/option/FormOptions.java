package io.contexa.contexaidentity.security.core.dsl.option;

import io.contexa.contexaidentity.security.core.asep.dsl.FormAsepAttributes;
import io.contexa.contexaidentity.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import lombok.Getter;
import org.springframework.context.ApplicationContext;
import org.springframework.util.Assert;

import java.util.Objects;

@Getter
public final class FormOptions extends AuthenticationProcessingOptions {

    private final String loginPage;
    private final String defaultLoginUrl;
    private final boolean explicitCustomLoginPage;
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
        this.defaultLoginUrl = builder.defaultLoginUrl;
        this.explicitCustomLoginPage = builder.explicitCustomLoginPage;
        this.usernameParameter = Objects.requireNonNull(builder.usernameParameter, "usernameParameter cannot be null");
        this.passwordParameter = Objects.requireNonNull(builder.passwordParameter, "passwordParameter cannot be null");
        this.defaultSuccessUrl = builder.defaultSuccessUrl;
        this.failureUrl = builder.failureUrl;
        this.permitAll = builder.permitAll;
        this.alwaysUseDefaultSuccessUrl = builder.alwaysUseDefaultSuccessUrl;
        this.rawFormLoginCustomizer = builder.rawFormLoginCustomizer;
        this.asepAttributes = builder.asepAttributes;
    }

    public static Builder builder(ApplicationContext applicationContext) {
        return new Builder(applicationContext, false);
    }

    public static Builder builderForMfa(ApplicationContext applicationContext) {
        return new Builder(applicationContext, true);
    }

    public boolean hasExplicitCustomLoginPage() {
        return explicitCustomLoginPage;
    }

    /**
     * Returns the effective login page URL for this form.
     * Priority: loginPage (custom) > defaultLoginUrl (auto-form URL change) > authUrlProvider default
     */
    public String getEffectiveLoginPage() {
        if (loginPage != null && explicitCustomLoginPage) {
            return loginPage;
        }
        if (defaultLoginUrl != null) {
            return defaultLoginUrl;
        }
        return loginPage;
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<FormOptions, Builder> {
        private String loginPage;
        private String defaultLoginUrl;
        private boolean explicitCustomLoginPage = false;
        private String usernameParameter = "username";
        private String passwordParameter = "password";
        private String defaultSuccessUrl;
        private String failureUrl;
        private boolean permitAll = false;
        private boolean alwaysUseDefaultSuccessUrl = false;
        private SafeHttpFormLoginCustomizer rawFormLoginCustomizer;
        private FormAsepAttributes asepAttributes;

        public Builder(ApplicationContext applicationContext) {
            this(applicationContext, false);
        }

        private Builder(ApplicationContext applicationContext, boolean isMfaMode) {
            Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null for FormOptions.Builder");

            AuthUrlProvider urlProvider = applicationContext.getBean(AuthUrlProvider.class);

            if (isMfaMode) {
                this.loginPage = urlProvider.getPrimaryLoginPage();
                this.defaultSuccessUrl = urlProvider.getPrimaryLoginSuccess();
                this.failureUrl = urlProvider.getPrimaryLoginFailure();
                super.loginProcessingUrl(urlProvider.getPrimaryFormLoginProcessing());
            } else {

                super.loginProcessingUrl(urlProvider.getSingleFormLoginProcessing());
            }

            super.order(100);
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder loginPage(String loginPage) {
            Assert.hasText(loginPage, "loginPage cannot be empty or null");
            this.loginPage = loginPage;
            this.explicitCustomLoginPage = true;
            return this;
        }

        public Builder defaultLoginUrl(String defaultLoginUrl) {
            Assert.hasText(defaultLoginUrl, "defaultLoginUrl cannot be empty or null");
            this.defaultLoginUrl = defaultLoginUrl;
            // Sync loginProcessingUrl to match the page URL (same as Spring Security standard)
            super.loginProcessingUrl(defaultLoginUrl);
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