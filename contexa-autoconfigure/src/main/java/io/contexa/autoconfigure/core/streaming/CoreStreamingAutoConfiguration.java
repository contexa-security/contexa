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
package io.contexa.autoconfigure.core.streaming;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProperties;
import io.contexa.contexacore.std.streaming.DefaultStandardStreamingService;
import io.contexa.contexacore.std.streaming.StandardStreamingService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration for StandardStreamingService.
 * Provides unified streaming API for Contexa platform.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "contexa.streaming", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(StreamingProperties.class)
public class CoreStreamingAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public StandardStreamingService standardStreamingService(
            StreamingProperties streamingProperties,
            ObjectMapper objectMapper) {
        return new DefaultStandardStreamingService(streamingProperties, objectMapper);
    }
}
