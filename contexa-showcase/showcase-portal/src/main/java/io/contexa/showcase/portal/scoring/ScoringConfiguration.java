package io.contexa.showcase.portal.scoring;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/** The one scoring rule over the stored runs (docs/showcase/데모-재설계.md 5.0). */
@Configuration(proxyBeanMethods = false)
public class ScoringConfiguration {

    @Bean
    RunScores runScores(NamedParameterJdbcTemplate jdbc, ScenarioCatalog scenarios, ObjectMapper json) {
        return new RunScores(jdbc, scenarios, json);
    }
}
