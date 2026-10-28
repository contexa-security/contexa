package io.contexa.showcase.portal.menu;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.live.RunCosts;
import io.contexa.showcase.portal.orchestrator.ModelPricing;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator;
import io.contexa.showcase.portal.scenario.AgentTaskCatalog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * docs/agent Agent중심-화면 AC-4a: the agent menu's beans. The daily refresh is off unless
 * {@code showcase.agent-menu.enabled} is true (it calls models); the operator can always start one. It exists where
 * the orchestrator does (control D is configured). Settings:
 * {@code showcase.agent-menu.daily-limit-usd} (default 2.00, what a day's job may spend) and
 * {@code showcase.agent-menu.at} (the UTC time of day, default 04:30, after the retention pass).
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "showcase.portal.controls", name = "d")
public class AgentMenuConfiguration {

    private static final Logger log = LoggerFactory.getLogger(AgentMenuConfiguration.class);

    @Bean
    AgentMenuStore agentMenuStore(NamedParameterJdbcTemplate jdbc) {
        return new AgentMenuStore(jdbc);
    }

    @Bean
    AgentMenuJob agentMenuJob(AgentTaskCatalog catalog, ObjectMapper json, RunOrchestrator orchestrator,
                              AgentMenuStore store, NamedParameterJdbcTemplate jdbc, ModelPricing pricing,
                              @Value("${showcase.agent-menu.daily-limit-usd:2.00}") double dailyLimitUsd) {
        return new AgentMenuJob(catalog, json, orchestrator::run, store, runIds -> spent(jdbc, pricing, runIds),
                dailyLimitUsd, Clock.systemUTC());
    }

    @Bean(destroyMethod = "shutdownNow")
    ExecutorService agentMenuExecutor() {
        return Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "showcase-agent-menu");
            thread.setDaemon(true);
            return thread;
        });
    }

    @Bean(destroyMethod = "shutdownNow")
    ScheduledExecutorService agentMenuScheduler(AgentMenuJob job, ExecutorService agentMenuExecutor,
                                                @Value("${showcase.agent-menu.enabled:false}") boolean enabled,
                                                @Value("${showcase.agent-menu.at:04:30}") String at) {
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "showcase-agent-menu-clock");
            thread.setDaemon(true);
            return thread;
        });
        if (enabled) {
            scheduler.scheduleAtFixedRate(() -> agentMenuExecutor.submit(() -> {
                try {
                    log.info("The agent menu's daily refresh: {}", job.refresh());
                } catch (RuntimeException e) {
                    log.error("The agent menu's daily refresh failed", e);
                }
            }), untilNext(Instant.now(), LocalTime.parse(at)).toMillis(), Duration.ofDays(1).toMillis(),
                    TimeUnit.MILLISECONDS);
        }
        return scheduler;
    }

    static Duration untilNext(Instant now, LocalTime at) {
        ZonedDateTime current = now.atZone(ZoneOffset.UTC);
        ZonedDateTime next = current.with(at);
        if (!next.isAfter(current)) {
            next = next.plusDays(1);
        }
        return Duration.between(current, next);
    }

    /** What the runs cost: their ledger rows, each model by its own price (the agent's own calls included). */
    static double spent(NamedParameterJdbcTemplate jdbc, ModelPricing pricing, Collection<String> runIds) {
        return RunCosts.byRun(jdbc, pricing, runIds).values().stream().mapToDouble(Double::doubleValue).sum();
    }
}
