package io.contexa.showcase.portal.share;

import io.contexa.showcase.portal.replay.ReplayGuard;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.visitor.VisitorStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/** End screen result and share cards; they need only the portal database and the published recordings. */
@Configuration(proxyBeanMethods = false)
public class ShareConfiguration {

    @Bean
    ExperienceScores experienceScores(ReplayViews replays, ReplayGuard guard, VisitorStore visitors) {
        return new ExperienceScores(replays, guard, visitors);
    }

    @Bean
    ShareStore shareStore(NamedParameterJdbcTemplate jdbc) {
        return new ShareStore(jdbc);
    }

    @Bean
    ShareCardRenderer shareCardRenderer() {
        return new ShareCardRenderer();
    }
}
