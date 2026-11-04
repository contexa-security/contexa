package io.contexa.autoconfigure.iam.sample;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;

/** A bean of a Contexa package (this package stands in for a Contexa library) with the {@code @PreAuthorize} Contexa's screens carry. */
public class ContexaSecuredSample {

    @PreAuthorize("denyAll()")
    public String locked() {
        return "reached";
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String adminOnly() {
        return "admin";
    }

    @Configuration(proxyBeanMethods = false)
    public static class Definition {
        @Bean
        ContexaSecuredSample contexaSecuredSample() {
            return new ContexaSecuredSample();
        }
    }
}
