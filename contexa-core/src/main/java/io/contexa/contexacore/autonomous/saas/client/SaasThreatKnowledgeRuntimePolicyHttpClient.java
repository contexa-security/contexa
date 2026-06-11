/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
