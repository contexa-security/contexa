package io.contexa.contexacore.autonomous.saas.client;

import io.contexa.contexacore.autonomous.saas.dto.ThreatKnowledgeRuntimePolicySnapshot;
import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestClient;

public class SaasThreatKnowledgeRuntimePolicyHttpClient {

    private final SaasForwardingProperties properties;
    private final SaasDecisionAccessTokenProvider accessTokenProvider;
    private final RestClient restClient;

    public SaasThreatKnowledgeRuntimePolicyHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        this(
                properties,
                accessTokenProvider,
                RestClient.builder()
                        .baseUrl(trimTrailingSlash(properties.getEndpoint()))
                        .build());
    }

    SaasThreatKnowledgeRuntimePolicyHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider,
            RestClient restClient) {
        this.properties = properties;
        this.accessTokenProvider = accessTokenProvider;
        this.restClient = restClient;
    }

    public ThreatKnowledgeRuntimePolicySnapshot fetchRuntimePolicy(int limit) {
        properties.validate();
        int safeLimit = Math.max(1, limit);
        ThreatKnowledgeRuntimePolicySnapshot snapshot = restClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path(properties.getThreatKnowledge().getRuntimePolicyEndpointPath())
                        .queryParam("limit", safeLimit)
                        .build())
                .headers(this::applyAuthorization)
                .retrieve()
                .body(ThreatKnowledgeRuntimePolicySnapshot.class);
        return snapshot != null ? snapshot : ThreatKnowledgeRuntimePolicySnapshot.empty();
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
