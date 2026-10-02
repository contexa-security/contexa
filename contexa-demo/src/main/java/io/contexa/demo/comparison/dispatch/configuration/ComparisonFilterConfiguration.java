package io.contexa.demo.comparison.dispatch.configuration;

import jakarta.servlet.Filter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration(proxyBeanMethods = false)
@Profile({"baseline", "contexa"})
public class ComparisonFilterConfiguration {

    @Bean
    FilterRegistrationBean<Filter> comparisonFilterRegistration(
            @Qualifier("comparisonDispatchFilter") Filter filter) {
        FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }
}
