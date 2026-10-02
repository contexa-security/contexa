package io.contexa.demo.observation.stream.configuration;

import io.contexa.demo.observation.request.service.WorkspaceEvidenceQuery;
import io.contexa.demo.observation.stream.repository.jdbc.JdbcObservationFeedRepository;
import io.contexa.demo.observation.stream.service.ObservationStream;
import io.contexa.demo.observation.stream.service.impl.BoundedObservationStream;
import io.contexa.demo.workspace.evidence.service.WorkspaceEvidenceScope;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;

import java.util.Map;

@Configuration(proxyBeanMethods = false)
@Profile("portal")
public class ObservationStreamConfiguration {

    @Bean
    ObservationStream observationStream(WorkspaceEvidenceQuery evidence, WorkspaceEvidenceScope scope,
            @Qualifier("baselineEvidenceJdbc") JdbcOperations baseline,
            @Qualifier("contexaEvidenceJdbc") JdbcOperations contexa) {
        return new BoundedObservationStream(evidence, Map.of(
                "baseline", new JdbcObservationFeedRepository(baseline),
                "contexa", new JdbcObservationFeedRepository(contexa)), scope);
    }
}
