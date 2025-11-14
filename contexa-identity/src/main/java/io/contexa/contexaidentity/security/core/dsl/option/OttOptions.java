package io.contexa.contexaidentity.security.core.dsl.option;

import io.contexa.contexaidentity.security.core.asep.dsl.OttAsepAttributes;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import lombok.Getter;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.Assert;

import java.util.Objects;

@Getter
public final class OttOptions extends AuthenticationProcessingOptions { // final class

    private final String tokenGeneratingUrl;
    private final String defaultSubmitPageUrl;
    private final String usernameParameter;
    private final String tokenParameter;
    private final boolean showDefaultSubmitPage;
    private final OneTimeTokenService oneTimeTokenService; // 필수
    private final OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;
    private final OttAsepAttributes asepAttributes;

    private OttOptions(Builder builder) {
        super(builder);
        this.tokenGeneratingUrl = Objects.requireNonNull(builder.tokenGeneratingUrl, "tokenGeneratingUrl cannot be null");
        this.defaultSubmitPageUrl = builder.defaultSubmitPageUrl;
        this.showDefaultSubmitPage = builder.showDefaultSubmitPage;
        this.usernameParameter = builder.usernameParameter;
        this.tokenParameter = builder.tokenParameter;
        this.oneTimeTokenService = Objects.requireNonNull(builder.oneTimeTokenService, "oneTimeTokenService cannot be null");
        this.tokenGenerationSuccessHandler = builder.tokenGenerationSuccessHandler;
        this.asepAttributes = builder.asepAttributes;

        if (this.showDefaultSubmitPage) {
            Assert.hasText(this.defaultSubmitPageUrl, "defaultSubmitPageUrl must be set if showDefaultSubmitPage is true");
        }
    }

    public static Builder builder(ApplicationContext applicationContext) {
        return new Builder(applicationContext, false);
    }

    public static Builder builderForMfa(ApplicationContext applicationContext) {
        return new Builder(applicationContext, true);
    }



    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<OttOptions, Builder> {
        private String tokenGeneratingUrl; // urlProvider에서 설정
        private String defaultSubmitPageUrl; // urlProvider에서 설정
        private String usernameParameter = "username"; // 기본값
        private String tokenParameter = "token"; // 기본값
        private boolean showDefaultSubmitPage = true; // 기본값
        private OneTimeTokenService oneTimeTokenService; // 생성자에서 주입
        private OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;
        private OttAsepAttributes asepAttributes;

        private Builder(ApplicationContext applicationContext, boolean isMfaMode) {
            Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null for OttOptions.Builder");

            // AuthUrlProvider를 통해 동적으로 URL 가져오기
            AuthUrlProvider urlProvider = applicationContext.getBean(AuthUrlProvider.class);

            if (isMfaMode) {
                // MFA Factor URL
                this.tokenGeneratingUrl = urlProvider.getMfaOttCodeGeneration();
                this.defaultSubmitPageUrl = urlProvider.getMfaOttChallengeUi();
                super.loginProcessingUrl(urlProvider.getMfaOttLoginProcessing());
            } else {
                // 단일 인증 URL
                this.tokenGeneratingUrl = urlProvider.getSingleOttCodeGeneration();
                this.defaultSubmitPageUrl = urlProvider.getSingleOttChallenge();
                super.loginProcessingUrl(urlProvider.getSingleOttLoginProcessing());
            }

            // 기존 서비스 주입
            this.oneTimeTokenService = applicationContext.getBean(OneTimeTokenService.class);
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder tokenGeneratingUrl(String url) {
            Assert.hasText(url, "tokenGeneratingUrl cannot be empty or null");
            this.tokenGeneratingUrl = url;
            return this;
        }

        public Builder defaultSubmitPageUrl(String url) {
            this.defaultSubmitPageUrl = url;
            return this;
        }

        public Builder getUsernameParameter() {
            this.usernameParameter = usernameParameter;
            return this;
        }

        public Builder getTokenParameter() {
            this.tokenParameter = tokenParameter;
            return this;
        }

        public Builder usernameParameter(String usernameParameter) {
            this.usernameParameter = usernameParameter;
            return this;
        }

        public Builder tokenParameter(String tokenParameter) {
            this.tokenParameter = tokenParameter;
            return this;
        }

        public Builder showDefaultSubmitPage(boolean show) {
            this.showDefaultSubmitPage = show;
            return this;
        }

        public Builder oneTimeTokenService(OneTimeTokenService service) {
            this.oneTimeTokenService = Objects.requireNonNull(service, "oneTimeTokenService cannot be null");
            return this;
        }

        public Builder tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
            this.tokenGenerationSuccessHandler = handler; // null 허용 가능 (기본 동작)
            return this;
        }

        public Builder asepAttributes(OttAsepAttributes attributes) {
            this.asepAttributes = attributes;
            return this;
        }

        @Override
        public OttOptions build() {
            Assert.hasText(loginProcessingUrl, "loginProcessingUrl must be set for OttOptions");
            if (this.showDefaultSubmitPage) {
                Assert.hasText(this.defaultSubmitPageUrl, "defaultSubmitPageUrl must be set if showDefaultSubmitPage is true");
            }
            Objects.requireNonNull(this.oneTimeTokenService, "oneTimeTokenService must be configured for OttOptions");
            return new OttOptions(this);
        }
    }
}
