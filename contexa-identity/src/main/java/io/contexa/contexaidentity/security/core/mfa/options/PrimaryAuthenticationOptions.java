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
    private final String primaryAuthStepId; // *** 1차 인증 AuthenticationStepConfig의 stepId ***

    // ⭐ 공통 1차 인증 UI 속성 (Form과 Rest 모두 사용)
    private final String loginPage;              // 로그인 페이지 URL
    private final String failureUrl;             // 인증 실패 시 리다이렉트 URL
    private final String loginProcessingUrl;     // 인증 처리 URL (기존에 Builder에만 있던 것을 필드로 승격)

    private PrimaryAuthenticationOptions(Builder builder) {
        this.formOptions = builder.formOptions;
        this.restOptions = builder.restOptions;
        this.primaryAuthType = builder.primaryAuthType;
        this.primaryAuthStepId = builder.primaryAuthStepId; // 빌더로부터 설정
        this.loginPage = builder.loginPage;
        this.failureUrl = builder.failureUrl;
        this.loginProcessingUrl = builder.loginProcessingUrl;

        if (formOptions != null && restOptions != null) {
            throw new IllegalArgumentException("Cannot configure both formLogin and restLogin for primary authentication.");
        }
        if (formOptions == null && restOptions == null) {
            throw new IllegalArgumentException("Either formLogin or restLogin must be configured for primary authentication.");
        }

        // loginProcessingUrl 검증
        Assert.hasText(loginProcessingUrl, "loginProcessingUrl cannot be null or empty for primary authentication options.");
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
        private String primaryAuthStepId;
        private String loginProcessingUrl;

        // ⭐ 공통 UI 속성
        private String loginPage;              // 로그인 페이지 URL
        private String failureUrl;             // 인증 실패 URL

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

        // loginProcessingUrl을 직접 설정할 수도 있지만, Form/Rest Options 에서 가져오는 것이 일반적
        public Builder loginProcessingUrl(String loginProcessingUrl) {
            this.loginProcessingUrl = loginProcessingUrl;
            return this;
        }

        public Builder primaryAuthStepId(String primaryAuthStepId) {
            this.primaryAuthStepId = primaryAuthStepId;
            return this;
        }

        // ⭐ 명시적으로 loginPage 오버라이드 가능 (DSL에서 사용)
        public Builder loginPage(String loginPage) {
            this.loginPage = loginPage;
            return this;
        }

        // ⭐ 명시적으로 failureUrl 오버라이드 가능 (DSL에서 사용)
        public Builder failureUrl(String failureUrl) {
            this.failureUrl = failureUrl;
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

            // loginPage 기본값 설정 (아직도 null이면)
            if (this.loginPage == null) {
                this.loginPage = "/mfa/login";
            }
            // failureUrl 기본값 설정 (아직도 null이면)
            if (this.failureUrl == null) {
                this.failureUrl = "/mfa/login?error";
            }

            // ⭐ URL 보안 검증 (Open Redirect 공격 방지)
            validateLoginPageUrl(this.loginPage);
            validateFailureUrl(this.failureUrl);

            return new PrimaryAuthenticationOptions(this);
        }

        /**
         * loginPage URL 보안 검증
         * Open Redirect 공격을 방지하기 위해 상대 경로만 허용
         *
         * @param loginPage 검증할 loginPage URL
         * @throws IllegalArgumentException 유효하지 않은 URL인 경우
         */
        private void validateLoginPageUrl(String loginPage) {
            if (loginPage == null) {
                return; // null은 허용 (REST의 경우)
            }

            // 빈 문자열 체크
            if (loginPage.trim().isEmpty()) {
                throw new IllegalArgumentException("loginPage cannot be empty string");
            }

            // 상대 경로 검증 (/ 로 시작해야 함)
            if (!loginPage.startsWith("/")) {
                throw new IllegalArgumentException(
                    "loginPage must be a relative path starting with '/'. " +
                    "External URLs are not allowed for security reasons. " +
                    "Provided: " + loginPage
                );
            }

            // 프로토콜 포함 여부 체크 (http://, https://, // 등)
            if (loginPage.contains("://") || loginPage.startsWith("//")) {
                throw new IllegalArgumentException(
                    "loginPage cannot contain protocol (http://, https://, etc.). " +
                    "Only relative paths are allowed. " +
                    "Provided: " + loginPage
                );
            }

            // JavaScript URL 체크
            if (loginPage.toLowerCase().startsWith("javascript:")) {
                throw new IllegalArgumentException(
                    "loginPage cannot be a JavaScript URL. " +
                    "Provided: " + loginPage
                );
            }

            // Data URL 체크
            if (loginPage.toLowerCase().startsWith("data:")) {
                throw new IllegalArgumentException(
                    "loginPage cannot be a data URL. " +
                    "Provided: " + loginPage
                );
            }
        }

        /**
         * failureUrl URL 보안 검증
         *
         * @param failureUrl 검증할 failureUrl
         * @throws IllegalArgumentException 유효하지 않은 URL인 경우
         */
        private void validateFailureUrl(String failureUrl) {
            if (failureUrl == null) {
                return; // null은 허용 (REST의 경우)
            }

            // failureUrl도 동일한 검증 로직 적용
            validateLoginPageUrl(failureUrl);
        }
    }
}
