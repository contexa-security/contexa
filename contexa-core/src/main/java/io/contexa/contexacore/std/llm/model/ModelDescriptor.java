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
package io.contexa.contexacore.std.llm.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ModelDescriptor {

    private String modelId;

    private String displayName;

    private String provider;

    private Integer tier;

    private String version;

    @Builder.Default
    private ModelCapabilities capabilities = ModelCapabilities.builder().build();

    @Builder.Default
    private ModelOptions options = ModelOptions.builder().build();

    @Builder.Default
    private ModelStatus status = ModelStatus.AVAILABLE;

    @Data
    @Builder
    public static class ModelCapabilities {
        @Builder.Default
        private boolean streaming = true;

        @Builder.Default
        private boolean toolCalling = false;

        @Builder.Default
        private boolean functionCalling = false;

        @Builder.Default
        private boolean multiModal = false;

        @Builder.Default
        private int maxTokens = 4096;

        @Builder.Default
        private int contextWindow = 4096;

        @Builder.Default
        private int maxOutputTokens = 4096;
    }

    @Data
    @Builder
    public static class ModelOptions {

        @Builder.Default
        private Double temperature = 0.7;

        @Builder.Default
        private Double topP = 0.9;

        private Integer topK;

        @Builder.Default
        private Double repetitionPenalty = 1.0;
    }

    public enum ModelStatus {
        AVAILABLE,
        UNAVAILABLE
    }




    public boolean supportsAdvancedFeatures() {
        return capabilities != null &&
               (capabilities.isToolCalling() ||
                capabilities.isFunctionCalling() ||
                capabilities.isMultiModal());
    }
}