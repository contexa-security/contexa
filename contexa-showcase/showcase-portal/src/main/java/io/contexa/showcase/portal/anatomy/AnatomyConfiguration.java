package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.retention.RetentionJob;
import io.contexa.showcase.portal.scoring.RunScores;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.time.Clock;

/** The verdict anatomy needs only the portal database (docs/showcase/데모-재설계.md 5.2). */
@Configuration(proxyBeanMethods = false)
public class AnatomyConfiguration {

    @Bean
    AnatomyStore anatomyStore(NamedParameterJdbcTemplate jdbc, ObjectMapper json, RunScores scores) {
        return new AnatomyStore(jdbc, json, scores, RetentionJob.Periods.plan().modelExchange(), Clock.systemUTC());
    }
}
