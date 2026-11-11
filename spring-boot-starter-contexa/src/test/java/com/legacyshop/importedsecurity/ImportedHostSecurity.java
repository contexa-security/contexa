package com.legacyshop.importedsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/** The security of an application (a package that is not Contexa's), which the application imports into its configuration. */
@Configuration(proxyBeanMethods = false)
public class ImportedHostSecurity {

    @Bean
    SecurityFilterChain importedChain(HttpSecurity http) throws Exception {
        return http.securityMatcher("/api/**").authorizeHttpRequests(requests -> requests.anyRequest().authenticated()).build();
    }
}
