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
package io.contexa.contexacommon.domain.response;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.enums.RiskLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.*;


@Getter
@Setter
public class BehavioralAnalysisResponse extends AIResponse {
    @JsonSetter(nulls = Nulls.SKIP)
    private String analysisId = UUID.randomUUID().toString();

    @JsonSetter(nulls = Nulls.SKIP)
    private String userId = "unknown";

    private double behavioralRiskScore = 0.0; 

    @JsonSetter(nulls = Nulls.SKIP)
    private RiskLevel riskLevel = RiskLevel.LOW;

    @JsonSetter(nulls = Nulls.SKIP)
    private String summary = ""; 

    @JsonSetter(nulls = Nulls.SKIP)
    private List<Anomaly> anomalies = new ArrayList<>();

    @JsonSetter(nulls = Nulls.SKIP)
    private List<Recommendation> recommendations = new ArrayList<>();

    @JsonSetter(nulls = Nulls.SKIP)
    private TimelineVisualizationData visualizationData;

    @Getter @Setter
    @AllArgsConstructor
    public static class Anomaly {
        private String type; 
        private String description;
    }

    @Getter @Setter
    @AllArgsConstructor
    public static class Recommendation {
        private String action; 
        private String reason;
    }

    @Getter @Setter
    public static class TimelineVisualizationData {
        private List<TimelineEvent> events;
    }

    @Getter @Setter
    public static class TimelineEvent {
        private String timestamp;
        private String type; 
        private String description;
        private boolean isAnomaly;
    }
}
