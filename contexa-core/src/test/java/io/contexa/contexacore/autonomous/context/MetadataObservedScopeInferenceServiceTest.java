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
package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.context.inference.MetadataObservedScopeInferenceService;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataObservedScopeInferenceServiceTest {

    @Test
    void inferShouldBuildObservedScopeFromProtectableHistoryMetadata() {
        MetadataObservedScopeInferenceService service = new MetadataObservedScopeInferenceService();

        SecurityEvent event = SecurityEvent.builder()
                .userId("alice")
                .build();
        event.addMetadata("requestPath", "/api/customer/export");
        event.addMetadata("httpMethod", "POST");
        event.addMetadata("protectableAccessHistory", List.of(
                java.util.Map.of("resourceId", "/api/customer/list", "actionFamily", "READ", "result", "ALLOWED"),
                java.util.Map.of("resourceId", "/api/customer/list", "actionFamily", "READ", "result", "ALLOWED"),
                java.util.Map.of("resourceId", "/api/customer/export", "actionFamily", "EXPORT", "result", "DENIED", "isSensitiveResource", true)));

        CanonicalSecurityContext context = CanonicalSecurityContext.builder()
                .resource(CanonicalSecurityContext.Resource.builder()
                        .resourceId("/api/customer/export")
                        .actionFamily("EXPORT")
                        .build())
                .build();

        CanonicalSecurityContext.ObservedScope observedScope = service.infer(event, context).orElseThrow();

        assertThat(observedScope.getProfileSource()).isEqualTo("PROTECTABLE_ACCESS_HISTORY");
        assertThat(observedScope.getRecentProtectableAccessCount()).isEqualTo(3);
        assertThat(observedScope.getRecentDeniedAccessCount()).isEqualTo(1);
        assertThat(observedScope.getRecentSensitiveAccessCount()).isEqualTo(1);
        assertThat(observedScope.getFrequentResources()).contains("/api/customer/list");
        assertThat(observedScope.getFrequentActionFamilies()).contains("READ");
    }
}
