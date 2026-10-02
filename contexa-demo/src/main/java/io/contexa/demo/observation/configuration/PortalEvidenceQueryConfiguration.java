package io.contexa.demo.observation.configuration;

import io.contexa.demo.observation.decision.repository.BaselineDecisionQuery;
import io.contexa.demo.observation.download.repository.jdbc.JdbcDownloadEvidenceRepository;
import io.contexa.demo.observation.decision.repository.NativeDecisionQuery;
import io.contexa.demo.observation.decision.repository.jdbc.JdbcNativeDecisionQuery;
import io.contexa.demo.observation.engine.repository.jdbc.JdbcEngineObservationRepository;
import io.contexa.demo.observation.health.repository.jdbc.JdbcCollectorStatusRepository;
import io.contexa.demo.observation.health.service.impl.StoredCollectionHealthQuery;
import io.contexa.demo.observation.http.repository.jdbc.JdbcBusinessHttpRepository;
import io.contexa.demo.observation.model.repository.jdbc.JdbcModelBoundaryQuery;
import io.contexa.demo.observation.provider.repository.jdbc.JdbcProviderHttpQuery;
import io.contexa.demo.observation.request.service.RequestEvidenceQuery;
import io.contexa.demo.observation.request.service.WorkspaceEvidenceQuery;
import io.contexa.demo.observation.request.service.impl.DefaultRequestEvidenceQuery;
import io.contexa.demo.observation.request.service.impl.DefaultWorkspaceEvidenceQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.request.repository.jdbc.JdbcBusinessRequestRepository;
import io.contexa.demo.workspace.evidence.service.WorkspaceEvidenceScope;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;

import java.util.Map;

@Configuration(proxyBeanMethods = false)
@Profile("portal")
public class PortalEvidenceQueryConfiguration {

    @Bean
    WorkspaceEvidenceQuery workspaceEvidenceQuery(@Qualifier("baselineEvidenceJdbc") JdbcOperations baseline,
            @Qualifier("contexaEvidenceJdbc") JdbcOperations contexa,
            @Qualifier("securityEvidenceJdbc") JdbcOperations security, DocumentCodec documents,
            WorkspaceEvidenceScope scope) {
        return new DefaultWorkspaceEvidenceQuery(Map.of(
                "baseline", query("baseline", baseline, new BaselineDecisionQuery(), documents),
                "contexa", query("contexa", contexa, new JdbcNativeDecisionQuery(security), documents)), scope);
    }

    private RequestEvidenceQuery query(String role, JdbcOperations jdbc, NativeDecisionQuery decisions,
            DocumentCodec documents) {
        return new DefaultRequestEvidenceQuery(new JdbcBusinessHttpRepository(jdbc),
                new JdbcBusinessRequestRepository(jdbc, documents), new JdbcEngineObservationRepository(jdbc, documents),
                decisions, role, new JdbcDownloadEvidenceRepository(jdbc),
                new StoredCollectionHealthQuery(new JdbcCollectorStatusRepository(jdbc), role),
                new JdbcModelBoundaryQuery(jdbc, documents), new JdbcProviderHttpQuery(jdbc, documents));
    }
}
