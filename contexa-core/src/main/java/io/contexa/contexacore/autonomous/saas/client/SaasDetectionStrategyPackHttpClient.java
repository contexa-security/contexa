package io.contexa.contexacore.autonomous.saas.client;

import io.contexa.contexacore.autonomous.saas.dto.DetectionStrategyPackSnapshot;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.web.client.RestClient;

public class SaasDetectionStrategyPackHttpClient extends AbstractSaasLearningPackHttpClient {

    public SaasDetectionStrategyPackHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        super(properties, accessTokenProvider);
    }

    SaasDetectionStrategyPackHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider,
            RestClient restClient) {
        super(properties, accessTokenProvider, restClient);
    }

    public DetectionStrategyPackSnapshot fetchPack(int limit) {
        properties.validate();
        int safeLimit = Math.max(1, limit);
        DetectionStrategyPackSnapshot snapshot = restClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path(properties.getDetectionStrategy().getEndpointPath())
                        .queryParam("limit", safeLimit)
                        .build())
                .headers(this::applyAuthorization)
                .retrieve()
                .body(DetectionStrategyPackSnapshot.class);
        return snapshot != null ? snapshot : DetectionStrategyPackSnapshot.empty();
    }
}
