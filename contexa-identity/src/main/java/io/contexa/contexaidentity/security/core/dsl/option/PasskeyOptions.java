package io.contexa.contexaidentity.security.core.dsl.option;

import io.contexa.contexaidentity.security.core.asep.dsl.PasskeyAsepAttributes;
import lombok.Getter;
import org.springframework.util.Assert;

import java.util.*;

@Getter
public final class PasskeyOptions extends AuthenticationProcessingOptions { // final class

    private final String assertionOptionsEndpoint; // 필수
    private final String rpName; // 필수
    private final String rpId;   // 필수
    private final Set<String> allowedOrigins;
    private final PasskeyAsepAttributes asepAttributes;

    private PasskeyOptions(Builder builder) {
        super(builder);
        this.assertionOptionsEndpoint = Objects.requireNonNull(builder.assertionOptionsEndpoint, "assertionOptionsEndpoint cannot be null");
        this.rpName = Objects.requireNonNull(builder.rpName, "rpName cannot be null");
        this.rpId = Objects.requireNonNull(builder.rpId, "rpId cannot be null");
        this.allowedOrigins = builder.allowedOrigins != null ?
                Collections.unmodifiableSet(new HashSet<>(builder.allowedOrigins)) : Collections.emptySet();
        this.asepAttributes = builder.asepAttributes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<PasskeyOptions, Builder> {
        private String assertionOptionsEndpoint = "/webauthn/assertion/options"; // 기본값
        private String rpName = "My Application";
        private String rpId;
        private Set<String> allowedOrigins = new HashSet<>();
        private PasskeyAsepAttributes asepAttributes;

        public Builder() {
            super.loginProcessingUrl("/login/webauthn"); // Passkey 인증 처리 URL 기본값
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder assertionOptionsEndpoint(String url) {
            Assert.hasText(url, "assertionOptionsEndpoint cannot be empty or null");
            this.assertionOptionsEndpoint = url;
            return this;
        }

        public Builder rpName(String rpName) {
            Assert.hasText(rpName, "rpName cannot be empty or null");
            this.rpName = rpName;
            return this;
        }

        public Builder rpId(String rpId) {
            Assert.hasText(rpId, "rpId cannot be empty or null");
            this.rpId = rpId;
            return this;
        }

        public Builder allowedOrigins(Set<String> origins) {
            this.allowedOrigins = (origins != null) ? new HashSet<>(origins) : new HashSet<>();
            return this;
        }

        public Builder allowedOrigins(List<String> origins) {
            this.allowedOrigins = (origins != null) ? new HashSet<>(origins) : new HashSet<>();
            return this;
        }

        public Builder allowedOrigins(String... origins) {
            this.allowedOrigins = (origins != null && origins.length > 0) ?
                    new HashSet<>(Arrays.asList(origins)) : new HashSet<>();
            return this;
        }

        public Builder asepAttributes(PasskeyAsepAttributes attributes) {
            this.asepAttributes = attributes;
            return this;
        }

        @Override
        public PasskeyOptions build() {
            Assert.hasText(loginProcessingUrl, "loginProcessingUrl must be set for PasskeyOptions");
            Assert.hasText(assertionOptionsEndpoint, "assertionOptionsEndpoint must be set for PasskeyOptions");
            Assert.hasText(rpName, "rpName must be set for PasskeyOptions");
            Assert.hasText(rpId, "rpId must be set for PasskeyOptions");
            return new PasskeyOptions(this);
        }
    }
}


