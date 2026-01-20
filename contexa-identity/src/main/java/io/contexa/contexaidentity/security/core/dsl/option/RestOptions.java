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
    private final RestAsepAttributes asepAttributes; 

    private RestOptions(Builder builder) {
        super(builder);
        this.usernameParameter = Objects.requireNonNull(builder.usernameParameter, "usernameParameter cannot be null");
        this.passwordParameter = Objects.requireNonNull(builder.passwordParameter, "passwordParameter cannot be null");
        this.asepAttributes = builder.asepAttributes; 
    }

    
    public static Builder builder(org.springframework.context.ApplicationContext applicationContext) {
        return new Builder(applicationContext, false);
    }

    
    public static Builder builderForMfa(org.springframework.context.ApplicationContext applicationContext) {
        return new Builder(applicationContext, true);
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<RestOptions, Builder> {
        private String usernameParameter = "username";
        private String passwordParameter = "password";
        private RestAsepAttributes asepAttributes; 

        
        public Builder(org.springframework.context.ApplicationContext applicationContext) {
            this(applicationContext, false);
        }

        
        private Builder(ApplicationContext applicationContext, boolean isMfaMode) {
            Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null for RestOptions.Builder");

            
            AuthUrlProvider urlProvider = applicationContext.getBean(AuthUrlProvider.class);

            if (isMfaMode) {
                
                super.loginProcessingUrl(urlProvider.getPrimaryRestLoginProcessing());
            } else {
                
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

        public Builder asepAttributes(RestAsepAttributes attributes) { 
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