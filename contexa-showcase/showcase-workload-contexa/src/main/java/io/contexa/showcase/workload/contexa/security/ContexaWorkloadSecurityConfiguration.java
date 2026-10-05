package io.contexa.showcase.workload.contexa.security;

import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.dsl.IdentityDslRegistry;
import io.contexa.showcase.workload.contexa.inbox.DemoInboxEmailService;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import java.time.Clock;

/**
 * Authentication of control D. The portal orchestrator signs in each run principal with JSON (restLogin) and
 * completes the engine's email one-time code factor through the demo inbox. Authorization stays with the
 * engine's policy manager, the same path a real Contexa application uses.
 */
@Configuration(proxyBeanMethods = false)
public class ContexaWorkloadSecurityConfiguration {

    @Bean
    public PlatformConfig platformDslConfig(ApplicationContext applicationContext,
                                            CustomDynamicAuthorizationManager authorizationManager) throws Exception {
        return new IdentityDslRegistry<HttpSecurity>(applicationContext)
                .global(http -> {
                    // Internal API reached only by the orchestrator over the private network, never by a browser.
                    http.csrf(AbstractHttpConfigurer::disable);
                    http.authorizeHttpRequests(requests -> requests.anyRequest().access(authorizationManager));
                })
                .mfa(mfa -> mfa.requiredFactors(1)
                        .primaryAuthentication(primary -> primary.restLogin(rest -> rest.defaultSuccessUrl("/")))
                        .ott(Customizer.withDefaults())
                        .order(100))
                .session(Customizer.withDefaults())
                .build();
    }

    @Bean
    public DemoInboxEmailService emailService() {
        return new DemoInboxEmailService(Clock.systemUTC());
    }
}
