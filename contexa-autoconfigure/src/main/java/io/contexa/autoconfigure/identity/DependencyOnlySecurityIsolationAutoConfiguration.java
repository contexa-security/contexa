/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.autoconfigure.identity;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Prevents Spring Boot's classpath-driven default login from changing a host that
 * only added the Contexa dependency. The chain never matches a request and is absent
 * as soon as the host supplies a chain or Contexa security is explicitly activated.
 */
@AutoConfiguration(
        before = SecurityAutoConfiguration.class,
        beforeName = "org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({HttpSecurity.class, SecurityFilterChain.class})
@ConditionalOnMissingBean({SecurityFilterChain.class, PlatformConfig.class})
public class DependencyOnlySecurityIsolationAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    SecurityFilterChain contexaDependencyOnlyIsolationFilterChain(HttpSecurity httpSecurity)
            throws Exception {
        httpSecurity
                .securityMatcher(request -> false)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());
        return httpSecurity.build();
    }
}
