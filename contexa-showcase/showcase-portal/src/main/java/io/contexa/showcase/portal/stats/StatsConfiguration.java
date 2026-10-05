package io.contexa.showcase.portal.stats;

import io.contexa.showcase.portal.replay.PairCatalog;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.time.Clock;

/** Execution statistics; needs only the portal database and the scenario and pair catalogs. */
@Configuration(proxyBeanMethods = false)
public class StatsConfiguration {

    @Bean
    ExecutionStats executionStats(NamedParameterJdbcTemplate jdbc, ScenarioCatalog scenarios, PairCatalog pairs) {
        return new ExecutionStats(jdbc, scenarios, pairs, Clock.systemUTC());
    }
}
