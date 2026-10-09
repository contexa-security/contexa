package io.contexa.showcase.portal.benchmark;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scoring.RunScores;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.time.Clock;

/**
 * The benchmark (docs/showcase/데모-재설계.md 5A.2, W5); needs only the portal database, the scoring rule and the
 * scenario catalog. Model prices are configured with their source; without them the cost per decision stays empty.
 *
 * <ul>
 *   <li>{@code showcase.benchmark.prices}: "model=input/cachedInput/output;..." in USD per million tokens</li>
 *   <li>{@code showcase.benchmark.price-source}: where those prices were read, shown next to the cost</li>
 * </ul>
 */
@Configuration(proxyBeanMethods = false)
public class BenchmarkConfiguration {

    @Bean
    BenchmarkService benchmarkService(NamedParameterJdbcTemplate jdbc, RunScores scores, ScenarioCatalog catalog,
                                      ObjectMapper objectMapper,
                                      @Value("${showcase.benchmark.prices:}") String prices,
                                      @Value("${showcase.benchmark.price-source:}") String priceSource) {
        return new BenchmarkService(jdbc, scores, catalog, objectMapper, BenchmarkService.prices(prices),
                priceSource.isBlank() ? null : priceSource, Clock.systemUTC());
    }
}
