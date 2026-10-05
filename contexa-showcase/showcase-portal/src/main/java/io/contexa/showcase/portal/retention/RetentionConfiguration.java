package io.contexa.showcase.portal.retention;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/** The daily retention pass at 03:30 UTC (P5-PRV-02); the operator API can also run it at once. */
@Configuration(proxyBeanMethods = false)
public class RetentionConfiguration {

    private static final Logger log = LoggerFactory.getLogger(RetentionConfiguration.class);
    static final LocalTime DAILY_AT = LocalTime.of(3, 30);

    @Bean
    RetentionJob retentionJob(NamedParameterJdbcTemplate jdbc, PlatformTransactionManager transactionManager,
                              ObjectMapper objectMapper) {
        return new RetentionJob(jdbc, new TransactionTemplate(transactionManager), objectMapper,
                RetentionJob.Periods.plan(), Clock.systemUTC());
    }

    @Bean(destroyMethod = "shutdownNow")
    ScheduledExecutorService retentionScheduler(RetentionJob job) {
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "showcase-retention");
            thread.setDaemon(true);
            return thread;
        });
        scheduler.scheduleAtFixedRate(() -> {
            try {
                job.run();
            } catch (RuntimeException e) {
                log.error("Retention pass failed", e);
            }
        }, untilNext(Instant.now()).toMillis(), Duration.ofDays(1).toMillis(), TimeUnit.MILLISECONDS);
        return scheduler;
    }

    static Duration untilNext(Instant now) {
        ZonedDateTime current = now.atZone(ZoneOffset.UTC);
        ZonedDateTime next = current.with(DAILY_AT);
        if (!next.isAfter(current)) {
            next = next.plusDays(1);
        }
        return Duration.between(current, next);
    }
}
