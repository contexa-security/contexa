package io.contexa.contexaidentity.security.core.mfa.options;

import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexacommon.enums.AuthType;
import lombok.Getter;
import org.springframework.util.Assert;

@Getter
public final class PrimaryAuthenticationOptions {
    private final FormOptions formOptions;
    private final RestOptions restOptions;
    private final AuthType primaryAuthType;
    private final String primaryAuthStepId; 

    private final String loginPage;              
    private final String failureUrl;             
    private final String loginProcessingUrl;     

    private PrimaryAuthenticationOptions(Builder builder) {
        this.formOptions = builder.formOptions;
        this.restOptions = builder.restOptions;
        this.primaryAuthType = builder.primaryAuthType;
        this.primaryAuthStepId = builder.primaryAuthStepId; 
        this.loginPage = builder.loginPage;
        this.failureUrl = builder.failureUrl;
        this.loginProcessingUrl = builder.loginProcessingUrl;

        if (formOptions != null && restOptions != null) {
            throw new IllegalArgumentException("Cannot configure both formLogin and restLogin for primary authentication.");
        }
        if (formOptions == null && restOptions == null) {
            throw new IllegalArgumentException("Either formLogin or restLogin must be configured for primary authentication.");
        }

        Assert.hasText(loginProcessingUrl, "loginProcessingUrl cannot be null or empty for primary authentication options.");

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
        private String primaryAuthStepId;
        private String loginProcessingUrl;

        private String loginPage;              
        private String failureUrl;             

        public Builder formOptions(FormOptions formOptions) {
            this.formOptions = formOptions;
            this.restOptions = null;
            if (formOptions != null) {
                this.loginProcessingUrl = formOptions.getLoginProcessingUrl();
                this.loginPage = formOptions.getLoginPage();
                this.failureUrl = formOptions.getFailureUrl();
            }
            return this;
        }

        public Builder restOptions(RestOptions restOptions) {
            this.restOptions = restOptions;
            this.formOptions = null;
            if (restOptions != null) {
                this.loginProcessingUrl = restOptions.getLoginProcessingUrl();

                if (this.loginPage == null) {
                    this.loginPage = "/mfa/login";
                }
                if (this.failureUrl == null) {
                    this.failureUrl = "/mfa/login?error";
                }
            }
            return this;
        }

        public Builder loginProcessingUrl(String loginProcessingUrl) {
            this.loginProcessingUrl = loginProcessingUrl;
            return this;
        }

        public Builder primaryAuthStepId(String primaryAuthStepId) {
            this.primaryAuthStepId = primaryAuthStepId;
            return this;
        }

        public Builder loginPage(String loginPage) {
            this.loginPage = loginPage;
            return this;
        }

        public Builder failureUrl(String failureUrl) {
            this.failureUrl = failureUrl;
            return this;
        }

        public PrimaryAuthenticationOptions build() {
            
            if (formOptions != null && loginProcessingUrl == null) {
                this.loginProcessingUrl = formOptions.getLoginProcessingUrl();
            } else if (restOptions != null && loginProcessingUrl == null) {
                this.loginProcessingUrl = restOptions.getLoginProcessingUrl();
            }
            Assert.hasText(loginProcessingUrl, "loginProcessingUrl could not be determined from FormOptions or RestOptions and was not set directly.");

            if (this.loginPage == null) {
                this.loginPage = "/mfa/login";
            }
            
            if (this.failureUrl == null) {
                this.failureUrl = "/mfa/login?error";
            }

            validateLoginPageUrl(this.loginPage);
            validateFailureUrl(this.failureUrl);

            return new PrimaryAuthenticationOptions(this);
        }

        private void validateLoginPageUrl(String loginPage) {
            if (loginPage == null) {
                return; 
            }

            if (loginPage.trim().isEmpty()) {
                throw new IllegalArgumentException("loginPage cannot be empty string");
            }

            if (!loginPage.startsWith("/")) {
                throw new IllegalArgumentException(
                    "loginPage must be a relative path starting with '/'. " +
                    "External URLs are not allowed for security reasons. " +
                    "Provided: " + loginPage
                );
            }

            if (loginPage.contains("://") || loginPage.startsWith("//")) {
                throw new IllegalArgumentException(
                    "loginPage cannot contain protocol (http://, https://, etc.). " +
                    "Only relative paths are allowed. " +
                    "Provided: " + loginPage
                );
            }

            if (loginPage.toLowerCase().startsWith("javascript:")) {
                throw new IllegalArgumentException(
                    "loginPage cannot be a JavaScript URL. " +
                    "Provided: " + loginPage
                );
            }

            if (loginPage.toLowerCase().startsWith("data:")) {
                throw new IllegalArgumentException(
                    "loginPage cannot be a data URL. " +
                    "Provided: " + loginPage
                );
            }
        }

        private void validateFailureUrl(String failureUrl) {
            if (failureUrl == null) {
                return; 
            }

            validateLoginPageUrl(failureUrl);
        }
    }
}
