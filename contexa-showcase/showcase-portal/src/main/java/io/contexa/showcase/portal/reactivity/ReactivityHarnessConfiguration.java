package io.contexa.showcase.portal.reactivity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/**
 * W6-1 (P6-CHANGE-2): what the harness runs need with or without control D: the record of the batch runs and the
 * variants the harness sends (the metrics that read the sealed prompts are in {@link ReactivityConfiguration}).
 */
@Configuration(proxyBeanMethods = false)
public class ReactivityHarnessConfiguration {

    @Bean
    ReactivityRuns reactivityRuns(NamedParameterJdbcTemplate jdbc) {
        return new ReactivityRuns(jdbc);
    }

    @Bean
    ReactionEvaluator reactionEvaluator() {
        return ReactionEvaluator.fromResources();
    }

    @Bean
    InjectionEvaluator injectionEvaluator() {
        return InjectionEvaluator.fromResources();
    }
}
