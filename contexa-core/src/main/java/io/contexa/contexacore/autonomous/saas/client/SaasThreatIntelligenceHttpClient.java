package io.contexa.contexacore.autonomous.saas.client;

import io.contexa.contexacore.autonomous.saas.dto.ThreatIntelligenceSnapshot;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestClient;

public class SaasThreatIntelligenceHttpClient {

    private final SaasForwardingProperties properties;
    private final SaasDecisionAccessTokenProvider accessTokenProvider;
    private final RestClient restClient;

    public SaasThreatIntelligenceHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        this(
                properties,
                accessTokenProvider,
                RestClient.builder()
                        .baseUrl(trimTrailingSlash(properties.getEndpoint()))
                        .build());
    }

    SaasThreatIntelligenceHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider,
            RestClient restClient) {
        this.properties = properties;
        this.accessTokenProvider = accessTokenProvider;
        this.restClient = restClient;
    }

    public ThreatIntelligenceSnapshot fetchSignals(int limit) {
        properties.validate();
        int safeLimit = Math.max(1, limit);
        ThreatIntelligenceSnapshot snapshot = restClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path(properties.getThreatIntelligence().getEndpointPath())
                        .queryParam("limit", safeLimit)
                        .build())
                .headers(this::applyAuthorization)
                .retrieve()
                .body(ThreatIntelligenceSnapshot.class);
        return snapshot != null ? snapshot : ThreatIntelligenceSnapshot.empty();
    }

    private void applyAuthorization(HttpHeaders headers) {
        headers.setBearerAuth(accessTokenProvider.getAccessToken());
    }

    private static String trimTrailingSlash(String value) {
        if (value == null || value.isBlank()) {
            return value;
        }
        String trimmed = value.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }
}
