package io.contexa.contexaidentity.security.core.dsl.option;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.PasskeyUrls;
import io.contexa.contexaidentity.security.core.asep.dsl.PasskeyAsepAttributes;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import lombok.Getter;
import org.springframework.context.ApplicationContext;
import org.springframework.util.Assert;

import java.util.*;

@Getter
public final class PasskeyOptions extends AuthenticationProcessingOptions { 

    private final String assertionOptionsEndpoint; 
    private final String rpName;
    private final String rpId;
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

    public static Builder builder(ApplicationContext applicationContext) {
        return new Builder(applicationContext, false);
    }

    public static Builder builderForMfa(ApplicationContext applicationContext) {
        return new Builder(applicationContext, true);
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<PasskeyOptions, Builder> {
        private String assertionOptionsEndpoint;
        private String rpName = "contexa-identity";
        private String rpId;
        private Set<String> allowedOrigins;
        private PasskeyAsepAttributes asepAttributes;

        private Builder(ApplicationContext applicationContext, boolean isMfaMode) {
            Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null for PasskeyOptions.Builder");

            AuthContextProperties authProps = applicationContext.getBean(AuthContextProperties.class);
            PasskeyUrls passkeyUrls = authProps.getUrls().getFactors().getPasskey();

            this.rpId = passkeyUrls.getRpId();
            this.rpName = passkeyUrls.getRpName();

            String configuredOrigins = passkeyUrls.getAllowedOrigins();
            if (configuredOrigins != null && !configuredOrigins.isBlank()) {
                this.allowedOrigins = Set.of(configuredOrigins.split(","));
            } else {
                String serverPort = applicationContext.getEnvironment().getProperty("server.port", "8080");
                this.allowedOrigins = Set.of("http://localhost:" + serverPort);
            }

            AuthUrlProvider urlProvider = applicationContext.getBean(AuthUrlProvider.class);

            if (isMfaMode) {
                
                this.assertionOptionsEndpoint = urlProvider.getMfaPasskeyAssertionOptions();
                super.loginProcessingUrl(urlProvider.getMfaPasskeyLoginProcessing());
            } else {
                
                this.assertionOptionsEndpoint = urlProvider.getSinglePasskeyAssertionOptions();
                super.loginProcessingUrl(urlProvider.getSinglePasskeyLoginProcessing());
            }
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

