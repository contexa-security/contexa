package io.contexa.showcase.portal.reactivity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/**
 * W7-13: the published prompt quality needs only the portal database to be read; publishing it needs control D
 * (ops PromptQualityOpsController).
 */
@Configuration(proxyBeanMethods = false)
public class PromptQualityConfiguration {

    @Bean
    PromptQualityPublications promptQualityPublications(NamedParameterJdbcTemplate jdbc) {
        return new PromptQualityPublications(jdbc);
    }
}
