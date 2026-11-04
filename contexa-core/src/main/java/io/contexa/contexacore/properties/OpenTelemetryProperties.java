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
package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "contexa.opentelemetry")
public class OpenTelemetryProperties {
    /**
     * Off by default. When on, Contexa builds an OpenTelemetry SDK, registers it as the JVM's global instance, installs a shutdown hook and
     * exports spans to {@link #exporterEndpoint}: an application that has its own OpenTelemetry (an agent, its own SDK) must not meet that
     * unless it asked for it.
     */
    private boolean enabled = false;
    private String serviceName = "contexa-core";
    private String exporterEndpoint = "http://localhost:4317";
    private double samplingProbability = 1.0;
}
