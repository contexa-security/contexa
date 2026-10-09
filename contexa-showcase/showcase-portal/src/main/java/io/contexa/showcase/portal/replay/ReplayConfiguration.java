package io.contexa.showcase.portal.replay;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scoring.RunScores;
import io.contexa.showcase.portal.spec.ExecutionSpecStore;
import io.contexa.showcase.portal.spec.ScoringContract;
import io.contexa.showcase.portal.visitor.VisitorCookies;
import io.contexa.showcase.portal.visitor.VisitorStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;

/**
 * The visitor-facing part of the portal: scenario and pair catalogs, recorded replays, execution specifications,
 * visitor cookie and predictions. It needs only the portal database.
 */
@Configuration(proxyBeanMethods = false)
public class ReplayConfiguration {

    @Bean
    ScenarioCatalog scenarioCatalog(ObjectMapper objectMapper) throws IOException {
        return new ScenarioCatalog(objectMapper);
    }

    @Bean
    PairCatalog pairCatalog(ObjectMapper objectMapper, ScenarioCatalog scenarios) throws IOException {
        return new PairCatalog(objectMapper, scenarios);
    }

    @Bean
    ExecutionSpecStore executionSpecStore(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper) {
        return new ExecutionSpecStore(jdbc, objectMapper);
    }

    @Bean
    ScoringContract scoringContract(ObjectMapper objectMapper) throws IOException {
        return new ScoringContract(objectMapper);
    }

    @Bean
    ReplayStore replayStore(NamedParameterJdbcTemplate jdbc, PlatformTransactionManager transactionManager,
                            ObjectMapper objectMapper) {
        return new ReplayStore(jdbc, new TransactionTemplate(transactionManager), objectMapper);
    }

    @Bean
    ReplayViews replayViews(PairCatalog pairs, ReplayStore store, ObjectMapper objectMapper, RunScores scores) {
        return new ReplayViews(pairs, store, objectMapper, scores);
    }

    @Bean
    ReplayConsistency replayConsistency(ReplayStore store, ExecutionSpecStore specs) {
        return new ReplayConsistency(store, specs);
    }

    @Bean
    ReplayGuard replayGuard(ReplayConsistency consistency) {
        return new ReplayGuard(consistency);
    }

    @Bean
    VisitorCookies visitorCookies(@Value("${showcase.internal.signing-key:}") String signingKey) {
        return new VisitorCookies(signingKey);
    }

    @Bean
    VisitorStore visitorStore(NamedParameterJdbcTemplate jdbc) {
        return new VisitorStore(jdbc);
    }
}
