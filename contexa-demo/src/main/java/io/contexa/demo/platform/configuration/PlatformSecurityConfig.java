package io.contexa.demo.platform.configuration;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.demo.identity.observation.AuthenticationObservationFilter;
import io.contexa.demo.security.policy.LabSecurityPolicy;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextRepository;

@Configuration(proxyBeanMethods = false)
@Profile("contexa")
public class PlatformSecurityConfig {

    @Bean
    PlatformConfig platformDslConfig(IdentityDslRegistry<HttpSecurity> registry, LabSecurityPolicy policy,
            @Qualifier("aiSessionSecurityContextRepository") SecurityContextRepository contexts,
            @Qualifier("customDynamicAuthorizationManager") AuthorizationManager<RequestAuthorizationContext> authorization,
            AuthUrlProvider urls, AuthenticationObservationFilter observations) throws Exception {
        return registry.global(http -> {
                    policy.apply(http, authorization);
                    http.securityContext(context -> context.securityContextRepository(contexts));
                    http.logout(logout -> logout.logoutUrl("/logout").logoutSuccessUrl("/session.html"));
                    http.addFilterAfter(observations, SecurityContextHolderFilter.class);
                }).form(form -> form.defaultLoginUrl(urls.getSingleFormLoginPage()).defaultSuccessUrl("/session.html")
                        .rawHttp(http -> http.securityMatcher(urls.getSingleFormLoginPage(),
                                urls.getSingleFormLoginProcessing())).order(50))
                .session(Customizer.withDefaults())
                .mfa(mfa -> mfa.requiredFactors(1)
                        .primaryAuthentication(auth -> auth.formLogin(form -> form.defaultSuccessUrl("/session.html")))
                        .passkey(Customizer.withDefaults()).ott(Customizer.withDefaults()).order(100))
                .session(Customizer.withDefaults()).build();
    }
}
