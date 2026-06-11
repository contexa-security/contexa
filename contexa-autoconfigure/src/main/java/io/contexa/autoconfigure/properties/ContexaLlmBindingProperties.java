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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
@ConfigurationProperties(prefix = "contexa.llm.bindings")
public class ContexaLlmBindingProperties {

    private Map<String, Binding> chat = new LinkedHashMap<>();
    private Map<String, Binding> embedding = new LinkedHashMap<>();

    @Data
    public static class Binding {
        private String beanName = "";
        private String provider = "";
        private String modelId = "";
        private List<String> aliases = new ArrayList<>();
        private boolean enabled = true;
        private boolean primary = false;
    }
}