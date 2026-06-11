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
package io.contexa.contexacore.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class SoarResponse extends AIResponse {

    private String analysisResult;

    private SessionState sessionState;

    @JsonSetter(nulls = Nulls.AS_EMPTY)
    @JsonDeserialize(using = StringToListDeserializer.class)
    private List<String> executedTools = new ArrayList<>();

    @JsonSetter(nulls = Nulls.AS_EMPTY)
    @JsonDeserialize(using = StringToListDeserializer.class)
    private List<String> recommendations = new ArrayList<>();

    private String summary;

    private String incidentId;

    private SoarContext.ThreatLevel threatLevel;

    private String sessionId;

    private LocalDateTime timestamp;

    private Map<String, Object> metadata;

    public SoarResponse() {
        this.timestamp = LocalDateTime.now();
        this.sessionState = SessionState.INITIALIZED;
        this.withExecutionTime(LocalDateTime.now());
    }

    public SoarResponse(String requestId, ExecutionStatus status) {
        this.timestamp = LocalDateTime.now();
        this.sessionState = SessionState.INITIALIZED;
        this.withExecutionTime(LocalDateTime.now());
    }
}