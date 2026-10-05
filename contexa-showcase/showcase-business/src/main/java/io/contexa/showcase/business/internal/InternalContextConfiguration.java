package io.contexa.showcase.business.internal;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;

import java.time.Clock;
import java.time.Duration;

/**
 * Registers the internal context filter ahead of every other filter. Imported only through
 * {@link EnableShowcaseInternalContext}, so applications that merely sign requests do not install it.
 */
public class InternalContextConfiguration {

    /** Largest accepted difference between the signing time and the workload clock. */
    public static final Duration MAX_CLOCK_SKEW = Duration.ofSeconds(60);

    @Bean
    public InternalContextSigner internalContextSigner(@Value("${showcase.internal.signing-key:}") String signingKey) {
        return new InternalContextSigner(signingKey);
    }

    @Bean
    public FilterRegistrationBean<InternalContextFilter> showcaseInternalContextFilter(InternalContextSigner signer) {
        FilterRegistrationBean<InternalContextFilter> registration = new FilterRegistrationBean<>(
                new InternalContextFilter(signer, Clock.systemUTC(), MAX_CLOCK_SKEW));
        registration.setName("showcaseInternalContextFilter");
        // Before the request context filter, Spring Security and the engine filters, all of which read the client.
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
        return registration;
    }
}
