package io.contexa.demo.identity.configuration;

import io.contexa.demo.identity.observation.AuthenticationObservationFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
public class AuthenticationObservationConfiguration {

    @Bean
    FilterRegistrationBean<AuthenticationObservationFilter> observationRegistration(
            AuthenticationObservationFilter filter) {
        var registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }
}
