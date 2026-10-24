package io.contexa.showcase.workload.contexa.security;

import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.OAuth2RequestScope;
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
 * completes the engine's email one-time code factor through the demo inbox. A run's agents call with tokens of the
 * engine's authorization server through the agents' flow (docs/agent A7-0). Authorization stays with the
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
                // docs/agent A7-0: the agents' flow. It takes only token requests (bearer tokens, the authorization
                // server's endpoints, its /agent sign-in), ordered before the people's session flow, which serves every
                // other request. A person signing in here for an agent workspace still completes the one-time code, and
                // an approved agent's own account signs in by the zero trust action alone (A1-13).
                .mfa(mfa -> mfa.name("agent").urlPrefix("/agent").requiredFactors(1)
                        .primaryAuthentication(primary -> primary.restLogin(rest -> rest.defaultSuccessUrl("/")))
                        .ott(Customizer.withDefaults())
                        .order(50))
                .oauth2(oauth2 -> oauth2.requestScope(OAuth2RequestScope.TOKEN_REQUESTS))
                .build();
    }

    @Bean
    public DemoInboxEmailService emailService() {
        return new DemoInboxEmailService(Clock.systemUTC());
    }
}
