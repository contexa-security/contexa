package io.contexa.contexaidentity.security.core.dsl.option;

import lombok.Getter;
import org.springframework.util.Assert;

@Getter
public final class RecoveryCodeOptions extends AuthenticationProcessingOptions {
    private final int codeLength;
    private final int numberOfCodesToGenerate;
    private final String emailOtpEndpoint;
    private final String smsOtpEndpoint;
    // private RecoveryCodeStore recoveryCodeStore; // 필요시 주입 또는 서비스로 분리

    private RecoveryCodeOptions(Builder builder) {
        super(builder);
        this.codeLength = builder.codeLength;
        this.numberOfCodesToGenerate = builder.numberOfCodesToGenerate;
        this.emailOtpEndpoint = builder.emailOtpEndpoint;
        this.smsOtpEndpoint = builder.smsOtpEndpoint;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends AbstractAuthenticationProcessingOptionsBuilder<RecoveryCodeOptions, Builder> {
        private int codeLength = 8;
        private int numberOfCodesToGenerate = 10;
        private String emailOtpEndpoint;
        private String smsOtpEndpoint;

        public Builder() {
            super.loginProcessingUrl("/login/recovery/verify"); // 복구 코드 검증 URL 예시
        }

        public Builder codeLength(int codeLength) {
            Assert.isTrue(codeLength > 0, "codeLength must be positive");
            this.codeLength = codeLength;
            return this;
        }

        public Builder numberOfCodesToGenerate(int numberOfCodesToGenerate) {
            Assert.isTrue(numberOfCodesToGenerate > 0, "numberOfCodesToGenerate must be positive");
            this.numberOfCodesToGenerate = numberOfCodesToGenerate;
            return this;
        }

        public Builder emailOtpEndpoint(String emailOtpEndpoint) {
            Assert.isTrue(emailOtpEndpoint != null, "emailOtpEndpoint must be positive");
            this.emailOtpEndpoint = emailOtpEndpoint;
            return this;
        }

        public Builder smsOtpEndpoint(String smsOtpEndpoint) {
            Assert.isTrue(smsOtpEndpoint != null, "smsOtpEndpoint must be positive");
            this.smsOtpEndpoint = smsOtpEndpoint;
            return this;
        }

        @Override
        protected Builder self() {
            return this;
        }

        @Override
        public RecoveryCodeOptions build() {
            return new RecoveryCodeOptions(this);
        }
    }
}
