package io.contexa.showcase.portal.hook;

import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.retention.RetentionJob;
import io.contexa.showcase.portal.scoring.RunScores;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.time.Clock;

/** The first screen's replay needs only the portal database and the stored runs. */
@Configuration(proxyBeanMethods = false)
public class HookConfiguration {

    @Bean
    HookStore hookStore(NamedParameterJdbcTemplate jdbc) {
        return new HookStore(jdbc);
    }

    @Bean
    HookViews hookViews(HookStore store, ReplayViews replays, RunScores scores) {
        return new HookViews(store, replays, scores, RetentionJob.Periods.plan().modelExchange(), Clock.systemUTC());
    }
}
