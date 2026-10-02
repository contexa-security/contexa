package io.contexa.demo.security.configuration;

import io.contexa.demo.entry.configuration.EntryProperties;
import io.contexa.demo.configuration.properties.LabProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration(proxyBeanMethods = false)
public class LabCorsConfiguration {

    @Bean
    CorsConfigurationSource corsConfigurationSource(EntryProperties entry, LabProperties lab) {
        CorsConfiguration cors = new CorsConfiguration();
        cors.setAllowedOrigins(List.of(entry.portalUrl()));
        cors.setAllowCredentials(true);
        cors.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        cors.setAllowedHeaders(List.of("Content-Type", "X-CSRF-TOKEN", "X-XSRF-TOKEN", "Accept",
                "X-Lab-Run-Id", "X-Lab-Step-Id"));
        cors.setExposedHeaders(List.of("X-Lab-Request-Id", "X-Lab-File-Id", "X-Lab-File-Sha256",
                "X-Lab-File-Reused", "Content-Disposition"));
        cors.setMaxAge(600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        if ("portal".equals(lab.role())) {
            CorsConfiguration reports = new CorsConfiguration(cors);
            reports.setAllowedOrigins(List.of(entry.portalUrl(), String.valueOf(lab.endpoints().baseline()),
                    String.valueOf(lab.endpoints().contexa())));
            source.registerCorsConfiguration("/api/lab/workspaces/requests/*/*/receipts", reports);
            CorsConfiguration csrf = new CorsConfiguration(reports);
            csrf.setAllowedMethods(List.of("GET", "OPTIONS"));
            source.registerCorsConfiguration("/api/auth/csrf", csrf);
            CorsConfiguration events = new CorsConfiguration(csrf);
            events.setAllowedHeaders(List.of("Accept", "Last-Event-ID"));
            source.registerCorsConfiguration("/api/lab/workspaces/requests/*/*/events", events);
        }
        source.registerCorsConfiguration("/api/**", cors);
        return source;
    }
}
