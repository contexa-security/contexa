package io.contexa.contexaidentity.security.core.dsl.configurer.impl;

import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexaidentity.security.filter.RestAuthenticationProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public abstract class AbstractRestAuthenticationConfigurer<T extends AbstractRestAuthenticationConfigurer<T, H>, H extends HttpSecurityBuilder<H>>
        extends AbstractAuthenticationConfigurer<T, H> {

    protected AbstractRestAuthenticationConfigurer() {
        super("/api/login");
    }

    @Override
    protected void beforeFilterCreation(H http, AuthenticationManager authenticationManager, ApplicationContext applicationContext) {
        UserDetailsService userDetailsService = applicationContext.getBean(UserDetailsService.class);
        PasswordEncoder passwordEncoder = applicationContext.getBean(PasswordEncoder.class);
        LoginPolicyHandler loginPolicyHandler = null;
        try {
            loginPolicyHandler = applicationContext.getBean(LoginPolicyHandler.class);
        } catch (Exception ignored) {
            // LoginPolicyHandler may not be available
        }
        http.authenticationProvider(new RestAuthenticationProvider(userDetailsService, passwordEncoder, loginPolicyHandler));
    }
}
