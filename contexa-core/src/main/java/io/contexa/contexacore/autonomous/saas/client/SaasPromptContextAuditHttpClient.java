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

import io.contexa.contexacore.properties.SaasForwardingProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

public class SaasPromptContextAuditHttpClient {

    private final SaasForwardingProperties properties;
    private final SaasDecisionAccessTokenProvider accessTokenProvider;
    private final RestClient restClient;

    public SaasPromptContextAuditHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider) {
        this(
                properties,
                accessTokenProvider,
                RestClient.builder()
                        .baseUrl(trimTrailingSlash(properties.getEndpoint()))
                        .build());
    }

    SaasPromptContextAuditHttpClient(
            SaasForwardingProperties properties,
            SaasDecisionAccessTokenProvider accessTokenProvider,
            RestClient restClient) {
        this.properties = properties;
        this.accessTokenProvider = accessTokenProvider;
        this.restClient = restClient;
    }

    public void send(String auditId, String payloadJson) {
        properties.validate();
        restClient.post()
                .uri(properties.getPromptContextAudit().getEndpointPath())
                .headers(headers -> applyAuthorization(headers, auditId))
                .contentType(MediaType.APPLICATION_JSON)
                .body(payloadJson)
                .retrieve()
                .toBodilessEntity();
    }

    private void applyAuthorization(HttpHeaders headers, String auditId) {
        headers.setBearerAuth(accessTokenProvider.getAccessToken());
        headers.set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        headers.set("Idempotency-Key", auditId);
        headers.set("X-Contexa-Audit-Id", auditId);
    }

    private static String trimTrailingSlash(String value) {
        if (value == null || value.isBlank()) {
            return value;
        }
        String trimmed = value.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }
}
