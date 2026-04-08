package io.contexa.contexacore.autonomous.saas.client;

import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestClient;

/**
 * Shared authorization and base-url support for SaaS learning pack clients.
 */
public abstract class AbstractSaasLearningPackHttpClient {

    protected final SaasForwardingProperties properties;
    protected final SaasDecisionAccessTokenProvider accessTokenProvider;
    protected final RestClient restClient;

    protected AbstractSaasLearningPackHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        this(
                properties,
                accessTokenProvider,
                RestClient.builder()
                        .baseUrl(trimTrailingSlash(properties.getEndpoint()))
                        .build());
    }

    protected AbstractSaasLearningPackHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider,
            RestClient restClient) {
        this.properties = properties;
        this.accessTokenProvider = accessTokenProvider;
        this.restClient = restClient;
    }

    protected void applyAuthorization(HttpHeaders headers) {
        headers.setBearerAuth(accessTokenProvider.getAccessToken());
    }

    protected static String trimTrailingSlash(String value) {
        if (value == null || value.isBlank()) {
            return value;
        }
        String trimmed = value.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }
}
