package io.contexa.showcase.portal.journey;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.anatomy.AnatomyStore;
import io.contexa.showcase.portal.hook.HookStore;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scoring.RunScores;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.time.Clock;

/** The visitor's journey, the quiz and the act-end cards need only the portal database and the stored runs. */
@Configuration(proxyBeanMethods = false)
public class JourneyConfiguration {

    @Bean
    JourneyStore journeyStore(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper) {
        return new JourneyStore(jdbc, objectMapper);
    }

    @Bean
    AnonymousTally anonymousTally(NamedParameterJdbcTemplate jdbc) {
        return new AnonymousTally(jdbc, Clock.systemUTC());
    }

    @Bean
    JourneyViews journeyViews(JourneyStore store, RunScores scores, ScenarioCatalog scenarios, AnonymousTally tally) {
        return new JourneyViews(store, scores, scenarios, tally, Clock.systemUTC());
    }

    @Bean
    ActEndCards actEndCards(NamedParameterJdbcTemplate jdbc, JourneyStore store, RunScores scores,
                            ScenarioCatalog scenarios, AnatomyStore anatomies, HookStore hook) {
        return new ActEndCards(jdbc, store, scores, scenarios, anatomies, hook);
    }
}
