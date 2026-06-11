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
package io.contexa.contexacore.autonomous.service.impl;

import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SoarContextProviderImplTest {

    @Test
    void createContextFromThreatIndicatorsShouldTolerateNullConfidence() {
        SecurityPlaneProperties properties = new SecurityPlaneProperties();
        properties.getAgent().setOrganizationId("org-1");

        SoarContextProviderImpl provider = new SoarContextProviderImpl(properties);
        ThreatIndicator indicator = ThreatIndicator.builder()
                .indicatorId("indicator-1")
                .type(ThreatIndicator.IndicatorType.IP_ADDRESS)
                .value("203.0.113.10")
                .severity(ThreatIndicator.Severity.CRITICAL)
                .confidence(null)
                .build();

        SoarContext context = provider.createContextFromThreatIndicators(List.of(indicator));

        assertThat(context).isNotNull();
        assertThat(context.isHumanApprovalNeeded()).isFalse();
        assertThat(context.getExecutionMode().name()).isEqualTo("ASYNC");
    }
}