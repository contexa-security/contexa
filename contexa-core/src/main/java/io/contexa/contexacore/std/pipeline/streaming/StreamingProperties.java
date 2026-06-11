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
package io.contexa.contexacore.std.pipeline.streaming;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Configuration properties for streaming pipeline.
 * Externalized configuration for streaming markers, timeouts, and retry settings.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "contexa.streaming")
public class StreamingProperties {

    private String finalResponseMarker = StreamingProtocol.FINAL_RESPONSE_MARKER;

    private String streamingMarker = StreamingProtocol.STREAMING_MARKER;

    private String jsonStartMarker = StreamingProtocol.JSON_START_MARKER;

    private String jsonEndMarker = StreamingProtocol.JSON_END_MARKER;

    private Duration timeout = Duration.ofMinutes(5);

    private int maxRetries = 3;

    private Duration retryDelay = Duration.ofSeconds(1);

    private double retryMultiplier = 1.5;

    private int markerBufferSize = 100;

    private boolean sentenceBufferingEnabled = true;
}
