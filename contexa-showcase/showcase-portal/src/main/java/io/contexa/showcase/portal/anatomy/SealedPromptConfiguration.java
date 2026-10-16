package io.contexa.showcase.portal.anatomy;

import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import io.contexa.showcase.portal.retention.RetentionJob;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.time.Clock;

/** W7-13: the sealed prompts of the visitor views are read from control D, so they exist only with control D. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "showcase.portal.controls", name = "d")
public class SealedPromptConfiguration {

    @Bean
    SealedPrompts sealedPrompts(NamedParameterJdbcTemplate jdbc, WorkloadAdmin admin) {
        return new SealedPrompts(jdbc, admin, Clock.systemUTC());
    }

    @Bean
    OtherBundles otherBundles(NamedParameterJdbcTemplate jdbc, SealedPrompts prompts) {
        return new OtherBundles(jdbc, prompts, RetentionJob.Periods.plan().modelExchange(), Clock.systemUTC());
    }
}
