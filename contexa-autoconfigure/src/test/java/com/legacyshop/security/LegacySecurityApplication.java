package com.legacyshop.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/** A legacy application (a package that is not Contexa's) with {@code @PreAuthorize} it may or may not have turned on. */
public class LegacySecurityApplication {

    public static class AppService {

        /** Would deny every call if method security were on for the application. */
        @PreAuthorize("denyAll()")
        public String locked() {
            return "reached";
        }
    }

    /** Method security is not enabled: the annotation is dormant. */
    @Configuration(proxyBeanMethods = false)
    public static class Dormant {
        @Bean
        AppService appService() {
            return new AppService();
        }
    }

    /** The application turned method security on itself. */
    @Configuration(proxyBeanMethods = false)
    @EnableMethodSecurity
    public static class Enabled {
        @Bean
        AppService appService() {
            return new AppService();
        }
    }
}
