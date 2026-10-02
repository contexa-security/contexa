package io.contexa.demo.observation.configuration;

import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.observation.decision.repository.NativeDecisionQuery;
import io.contexa.demo.observation.download.repository.DownloadEvidenceRepository;
import io.contexa.demo.observation.engine.repository.EngineObservationRepository;
import io.contexa.demo.observation.health.repository.CollectorStatusRepository;
import io.contexa.demo.observation.health.service.impl.StoredCollectionHealthQuery;
import io.contexa.demo.observation.http.repository.BusinessHttpRepository;
import io.contexa.demo.observation.model.repository.ModelBoundaryQuery;
import io.contexa.demo.observation.provider.repository.ProviderHttpQuery;
import io.contexa.demo.observation.request.service.RequestEvidenceQuery;
import io.contexa.demo.observation.request.service.impl.DefaultRequestEvidenceQuery;
import io.contexa.demo.work.request.repository.BusinessRequestRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration(proxyBeanMethods = false)
@Profile({"baseline", "contexa"})
public class LocalEvidenceQueryConfiguration {

    @Bean
    RequestEvidenceQuery requestEvidenceQuery(BusinessHttpRepository http, BusinessRequestRepository requests,
            EngineObservationRepository events, NativeDecisionQuery decisions, LabProperties properties,
            DownloadEvidenceRepository downloads, CollectorStatusRepository statuses, ModelBoundaryQuery models,
            ProviderHttpQuery provider) {
        return new DefaultRequestEvidenceQuery(http, requests, events, decisions, properties.role(), downloads,
                new StoredCollectionHealthQuery(statuses, properties.role()), models, provider);
    }
}
