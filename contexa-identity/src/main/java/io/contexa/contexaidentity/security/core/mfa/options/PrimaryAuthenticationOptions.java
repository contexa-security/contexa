package io.contexa.contexaidentity.security.core.mfa.options;

import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.enums.AuthType;
import lombok.Getter;
import org.springframework.util.Assert;

@Getter
public final class PrimaryAuthenticationOptions {
    private final FormOptions formOptions;
    private final RestOptions restOptions;
    private final AuthType primaryAuthType;
    private final String primaryAuthStepId; // *** 1차 인증 AuthenticationStepConfig의 stepId ***

    private PrimaryAuthenticationOptions(Builder builder) {
        this.formOptions = builder.formOptions;
        this.restOptions = builder.restOptions;
        this.primaryAuthType = builder.primaryAuthType;
        this.primaryAuthStepId = builder.primaryAuthStepId; // 빌더로부터 설정

        if (formOptions != null && restOptions != null) {
            throw new IllegalArgumentException("Cannot configure both formLogin and restLogin for primary authentication.");
        }
        if (formOptions == null && restOptions == null) {
            throw new IllegalArgumentException("Either formLogin or restLogin must be configured for primary authentication.");
        }
//        Assert.notNull(primaryAuthType, "PrimaryAuthType cannot be null.");
        // primaryAuthStepId는 PrimaryAuthDslConfigurerImpl 에서 설정되므로 null이 아님을 보장해야 함
//        Assert.hasText(primaryAuthStepId, "PrimaryAuthStepId cannot be null or empty for primary authentication options.");
    }

    public boolean isFormLogin() {
        return formOptions != null;
    }

    public boolean isRestLogin() {
        return restOptions != null;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private FormOptions formOptions;
        private RestOptions restOptions;
        private AuthType primaryAuthType;
        private String primaryAuthStepId; // 추가
        private String loginProcessingUrl;

        public Builder formOptions(FormOptions formOptions) {
            this.formOptions = formOptions;
            this.restOptions = null;
            if (formOptions != null) {
                this.loginProcessingUrl = formOptions.getLoginProcessingUrl();
            }
            return this;
        }

        public Builder restOptions(RestOptions restOptions) {
            this.restOptions = restOptions;
            this.formOptions = null;
            if (restOptions != null) {
                this.loginProcessingUrl = restOptions.getLoginProcessingUrl();
            }
            return this;
        }

        // loginProcessingUrl을 직접 설정할 수도 있지만, Form/Rest Options 에서 가져오는 것이 일반적
        public Builder loginProcessingUrl(String loginProcessingUrl) {
            this.loginProcessingUrl = loginProcessingUrl;
            return this;
        }

        public Builder primaryAuthStepId(String primaryAuthStepId) {
            this.primaryAuthStepId = primaryAuthStepId;
            return this;
        }

        public PrimaryAuthenticationOptions build() {
            // loginProcessingUrl이 설정되었는지 최종 확인
            if (formOptions != null && loginProcessingUrl == null) {
                this.loginProcessingUrl = formOptions.getLoginProcessingUrl();
            } else if (restOptions != null && loginProcessingUrl == null) {
                this.loginProcessingUrl = restOptions.getLoginProcessingUrl();
            }
            Assert.hasText(loginProcessingUrl, "loginProcessingUrl could not be determined from FormOptions or RestOptions and was not set directly.");
            return new PrimaryAuthenticationOptions(this);
        }
    }
}
