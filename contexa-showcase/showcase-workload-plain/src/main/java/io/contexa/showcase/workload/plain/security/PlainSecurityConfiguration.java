package io.contexa.showcase.workload.plain.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.context.BusinessContextLookup;
import io.contexa.showcase.business.work.WorkDatabase;
import io.contexa.showcase.workload.plain.rules.ContextLookupRules;
import io.contexa.showcase.workload.plain.rules.ThresholdRules;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import java.time.Clock;
import java.util.Set;
import io.contexa.showcase.business.ProductionSafety;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import java.util.List;

/**
 * Security chain of a plain control. The instance's control (B, C1 or C2, property showcase.control) selects the
 * authorization rules on top of the shared role-based policy (docs/showcase/ADR.md ADR-20, ADR-22).
 */
@Configuration(proxyBeanMethods = false)
public class PlainSecurityConfiguration {

    private static final Set<String> CONTROLS = Set.of("B", "C1", "C2");

    /** Refuses a production start with a default database password (deck p.37, P5-SEC-02). */
    @Bean
    InitializingBean productionSafetyCheck(Environment environment) {
        return () -> ProductionSafety.verify(environment, List.of());
    }

    @Bean
    PasswordEncoder plainPasswordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    PlainUserDetailsService plainUserDetailsService(WorkDatabase database) {
        return new PlainUserDetailsService(database);
    }

    @Bean
    AuthenticationManager plainAuthenticationManager(PlainUserDetailsService users, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(users);
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }

    @Bean
    SecurityContextRepository plainSecurityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    DecisionRecorder decisionRecorder(WorkDatabase database, ObjectMapper objectMapper) {
        return new DecisionRecorder(database, objectMapper, Clock.systemUTC());
    }

    @Bean
    ControlAuthorizationManager controlAuthorizationManager(@Value("${showcase.control}") String control,
                                                            BusinessContextLookup lookup, DecisionRecorder recorder,
                                                            WorkDatabase database) {
        if (!CONTROLS.contains(control)) {
            throw new IllegalStateException("showcase.control of the plain workload must be B, C1 or C2: " + control);
        }
        return new ControlAuthorizationManager(control, new ThresholdRules(lookup), new ContextLookupRules(lookup),
                recorder, database, Clock.systemUTC());
    }

    @Bean
    SecurityFilterChain plainSecurityFilterChain(HttpSecurity http, ControlAuthorizationManager authorization,
                                                 SecurityContextRepository securityContextRepository,
                                                 AuthenticationManager authenticationManager,
                                                 @Value("${showcase.control}") String control,
                                                 ObjectMapper objectMapper) throws Exception {
        JsonSecurityResponses responses = new JsonSecurityResponses(control, objectMapper);
        http.securityMatcher("/**")
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        // The management API is guarded by the internal signature (InternalApiGuardFilter).
                        .requestMatchers("/internal/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/login").permitAll()
                        .requestMatchers("/api/**").access(authorization)
                        .anyRequest().denyAll())
                .authenticationManager(authenticationManager)
                .securityContext(context -> context.securityContextRepository(securityContextRepository))
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(responses)
                        .accessDeniedHandler(responses))
                // Internal API reached only by the orchestrator, like control D (ADR-16).
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable);
        return http.build();
    }
}
