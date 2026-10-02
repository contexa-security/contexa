package io.contexa.demo.security.configuration;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration(proxyBeanMethods = false)
@Profile("public")
public class PublicCorsFilterConfiguration {

    @Bean
    FilterRegistrationBean<CorsFilter> publicCorsFilter(@Qualifier("corsConfigurationSource") CorsConfigurationSource source) {
        FilterRegistrationBean<CorsFilter> registration = new FilterRegistrationBean<>(new CorsFilter(source));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return registration;
    }
}
