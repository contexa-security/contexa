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
package io.contexa.autoconfigure.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "contexa.llm.selection")
public class ContexaLlmSelectionProperties {

    private Chat chat = new Chat();
    private Embedding embedding = new Embedding();

    public enum Mode {
        DYNAMIC_PRIORITY,
        FIXED,
        SPRING_PRIMARY
    }

    @Data
    public static class Chat {
        private Mode mode = Mode.DYNAMIC_PRIORITY;
        private String priority = "openai,anthropic,ollama";
    }

    @Data
    public static class Embedding {
        private Mode mode = Mode.FIXED;
        private String priority = "openai";
    }
}
