package io.contexa.demo.observation.request.service.impl;

import io.contexa.demo.observation.decision.dto.NativeDecisionView;
import io.contexa.demo.observation.download.repository.DownloadEvidenceRepository;
import io.contexa.demo.observation.decision.repository.NativeDecisionQuery;
import io.contexa.demo.observation.engine.repository.EngineObservationRepository;
import io.contexa.demo.observation.health.service.CollectionHealthQuery;
import io.contexa.demo.observation.http.dto.BusinessHttpObservation;
import io.contexa.demo.observation.http.repository.BusinessHttpRepository;
import io.contexa.demo.observation.model.dto.ModelBoundaryEvidence;
import io.contexa.demo.observation.model.repository.ModelBoundaryQuery;
import io.contexa.demo.observation.provider.dto.ProviderHttpEvidence;
import io.contexa.demo.observation.provider.repository.ProviderHttpQuery;
import io.contexa.demo.observation.request.dto.RequestEvidenceView;
import io.contexa.demo.observation.request.service.RequestEvidenceQuery;
import io.contexa.demo.work.request.repository.BusinessRequestRepository;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

public class DefaultRequestEvidenceQuery implements RequestEvidenceQuery {

    private final BusinessHttpRepository http;
    private final BusinessRequestRepository requests;
    private final EngineObservationRepository events;
    private final NativeDecisionQuery decisions;
    private final String role;
    private final DownloadEvidenceRepository downloads;
    private final CollectionHealthQuery health;
    private final ModelBoundaryQuery models;
    private final ProviderHttpQuery provider;

    public DefaultRequestEvidenceQuery(BusinessHttpRepository http, BusinessRequestRepository requests,
            EngineObservationRepository events, NativeDecisionQuery decisions, String role,
            DownloadEvidenceRepository downloads, CollectionHealthQuery health, ModelBoundaryQuery models,
            ProviderHttpQuery provider) {
        this.provider = provider;
        this.models = models;
        this.health = health;
        this.http = http;
        this.requests = requests;
        this.events = events;
        this.decisions = decisions;
        this.role = role;
        this.downloads = downloads;
    }

    @Override
    public RequestEvidenceView find(UUID requestId, UUID visitorId) {
        BusinessHttpObservation observation = http.find(requestId, visitorId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        List<NativeDecisionView> finalDecisions;
        String state = "contexa".equals(role) ? "READ" : "NOT_APPLICABLE";
        try {
            finalDecisions = decisions.find(requestId);
        } catch (DataAccessException unavailable) {
            finalDecisions = List.of();
            state = "UNAVAILABLE";
        }
        ProviderHttpEvidence providerEvidence = providerEvidence(requestId);
        return new RequestEvidenceView(role, observation, requests.find(requestId).orElse(null),
                events.find(requestId), finalDecisions, providerEvidence.state(), state,
                downloads.find(requestId).orElse(null), health.find(observation.collectorInstanceId()),
                modelEvidence(requestId), providerEvidence);
    }

    private ProviderHttpEvidence providerEvidence(UUID requestId) {
        if (!"contexa".equals(role)) {
            return new ProviderHttpEvidence("NOT_APPLICABLE", false, List.of());
        }
        try {
            return provider.find(requestId);
        } catch (DataAccessException unavailable) {
            return new ProviderHttpEvidence("UNAVAILABLE", false, List.of());
        }
    }

    private ModelBoundaryEvidence modelEvidence(UUID requestId) {
        if (!"contexa".equals(role)) {
            return new ModelBoundaryEvidence("NOT_APPLICABLE", false, List.of());
        }
        try {
            return models.find(requestId);
        } catch (DataAccessException unavailable) {
            return new ModelBoundaryEvidence("UNAVAILABLE", false, List.of());
        }
    }
}
