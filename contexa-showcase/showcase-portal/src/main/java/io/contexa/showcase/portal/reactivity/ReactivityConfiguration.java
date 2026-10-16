package io.contexa.showcase.portal.reactivity;

import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/** W6-1 (P6-CHANGE-2): the harness metrics of the measurement harness. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "showcase.portal.controls", name = "d")
public class ReactivityConfiguration {

    @Bean
    ReactivityService reactivityService(WorkloadAdmin admin, NamedParameterJdbcTemplate jdbc,
                                        ReactionEvaluator reaction, InjectionEvaluator injection,
                                        ReactivityRuns runs) {
        return new ReactivityService(admin, jdbc, DeliveryEvaluator.fromResources(), reaction, injection, runs);
    }
}
