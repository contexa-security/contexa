package io.contexa.demo.observation.provider.configuration;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.client.RestClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.client.ClientHttpRequestInterceptor;

@Configuration(proxyBeanMethods = false)
@Profile("contexa")
public class ProviderObservationConfiguration {

    @Bean
    RestClientCustomizer providerObservationCustomizer(
            @Qualifier("providerObservationInterceptor") ClientHttpRequestInterceptor interceptor,
            @Qualifier("workspaceProviderBudgetInterceptor") ClientHttpRequestInterceptor budget) {
        return builder -> builder.requestInterceptor(budget).requestInterceptor(interceptor);
    }
}
