package io.contexa.demo.security.configuration;

import io.contexa.demo.identity.observation.AuthenticationObservationFilter;
import io.contexa.demo.security.policy.LabSecurityPolicy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;

@Configuration(proxyBeanMethods = false)
@Profile({"portal", "baseline"})
public class StandardSecurityConfiguration {

    @Bean
    SecurityFilterChain labSecurityFilterChain(HttpSecurity http, LabSecurityPolicy policy,
            AuthenticationObservationFilter observations) throws Exception {
        policy.apply(http, null);
        http.formLogin(form -> form.defaultSuccessUrl("/session.html", true));
        http.logout(logout -> logout.logoutUrl("/logout").logoutSuccessUrl("/session.html"));
        http.addFilterAfter(observations, SecurityContextHolderFilter.class);
        return http.build();
    }
}
