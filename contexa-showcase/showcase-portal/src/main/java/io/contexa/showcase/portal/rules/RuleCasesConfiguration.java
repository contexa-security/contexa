package io.contexa.showcase.portal.rules;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import io.contexa.showcase.portal.replay.ReplayStore;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.time.Clock;

/** The rule-limits scene's cases; needs only the portal database, the stored runs and the scenario catalog. */
@Configuration(proxyBeanMethods = false)
public class RuleCasesConfiguration {

    @Bean
    RuleCases ruleCases(NamedParameterJdbcTemplate jdbc, ReplayStore store, ReplayViews views,
                        ScenarioCatalog scenarios) {
        return new RuleCases(jdbc, store, views, scenarios, Clock.systemUTC());
    }

    /**
     * The rule classes' decisions of the cases under a visitor's settings (H-10), asked of the plain workload; only
     * with the control addresses configured, as the workload client is (OrchestrationConfiguration).
     */
    @Bean
    @ConditionalOnProperty(prefix = "showcase.portal.controls", name = "d")
    RuleEvaluation ruleEvaluation(RuleCases cases, WorkloadAdmin admin, ObjectMapper objectMapper) {
        return new RuleEvaluation(cases, admin, objectMapper, Clock.systemUTC());
    }
}
