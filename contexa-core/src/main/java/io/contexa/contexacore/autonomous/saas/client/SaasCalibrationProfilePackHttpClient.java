package io.contexa.contexacore.autonomous.saas.client;

import io.contexa.contexacore.autonomous.saas.dto.CalibrationProfilePackSnapshot;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.web.client.RestClient;

public class SaasCalibrationProfilePackHttpClient extends AbstractSaasLearningPackHttpClient {

    public SaasCalibrationProfilePackHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        super(properties, accessTokenProvider);
    }

    SaasCalibrationProfilePackHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider,
            RestClient restClient) {
        super(properties, accessTokenProvider, restClient);
    }

    public CalibrationProfilePackSnapshot fetchPack(int limit) {
        properties.validate();
        int safeLimit = Math.max(1, limit);
        CalibrationProfilePackSnapshot snapshot = restClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path(properties.getCalibrationProfile().getEndpointPath())
                        .queryParam("limit", safeLimit)
                        .build())
                .headers(this::applyAuthorization)
                .retrieve()
                .body(CalibrationProfilePackSnapshot.class);
        return snapshot != null ? snapshot : CalibrationProfilePackSnapshot.empty();
    }
}
