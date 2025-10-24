package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;
import io.contexa.contexaidentity.security.enums.AuthType;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class PasskeyAuthenticationAdapter extends AbstractAuthenticationAdapter<PasskeyOptions> {

    @Override
    public String getId() {
        return AuthType.PASSKEY.name().toLowerCase();
    }

    @Override
    public int getOrder() {
        return 400;
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http, PasskeyOptions opts,
                                         AuthenticationFlowConfig currentFlow,
                                         PlatformAuthenticationSuccessHandler successHandler,
                                         PlatformAuthenticationFailureHandler failureHandler) throws Exception {

        http.webAuthn(web -> {
            web.rpName(opts.getRpName())
                    .rpId(opts.getRpId())
                    .allowedOrigins(opts.getAllowedOrigins());
        });
    }
}

