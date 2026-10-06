package io.contexa.showcase.portal.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import io.contexa.showcase.business.ProductionSafety;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;

/**
 * Visitors never log in to see the experience. The portal exposes the web application and its health
 * endpoint; the visitor APIs under /api are opened phase by phase with their own rules (P2: visitor state, pairs,
 * replays, execution specifications and predictions, the last one protected by the CSRF token).
 */
@Configuration(proxyBeanMethods = false)
public class PortalSecurityConfiguration {

    /**
     * Refuses a production start with a default secret, a cookie without Secure, the development-only forced decision,
     * client addresses taken from untrusted proxies, or live runs without the human check (deck p.37, P5-SEC-02,
     * P5-SEC-05).
     */
    @Bean
    InitializingBean productionSafetyCheck(Environment environment) {
        return () -> ProductionSafety.verify(environment, PortalProductionRules.problems(environment));
    }

    /**
     * Operator API on the operator port only (OpsPortConfiguration rejects /ops on the visitor port). The port is
     * never published by the production-shaped stack.
     */
    @Bean
    @Order(1)
    SecurityFilterChain opsSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/ops/**")
                .authorizeHttpRequests(requests -> requests.anyRequest().permitAll())
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable);
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain portalSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/visitor", "/api/pairs", "/api/replays/*",
                                "/api/specs/*", "/api/combinations", "/api/combinations/*",
                                "/api/stats", "/api/results/*")
                        .permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/predictions", "/api/shares").permitAll()
                        // Live runs (P3, P4); the endpoints exist only with showcase.live.enabled.
                        .requestMatchers(HttpMethod.GET, "/api/live/config", "/api/live/runs/current",
                                "/api/live/runs/current/result").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/live/runs", "/api/live/combinations",
                                "/api/live/runs/current/*").permitAll()
                        .requestMatchers("/api/**").denyAll()
                        .requestMatchers(HttpMethod.GET, "/**").permitAll()
                        .anyRequest().denyAll())
                // The web application reads the token cookie and sends it back unchanged in the header.
                .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable);
        return http.build();
    }
}
