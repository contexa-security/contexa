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
package io.contexa.autoconfigure.core.autonomous;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** An operator who looks the limit of new-context decisions up in the IDE finds what it does and its defaults. */
class NewContextLimitMetadataTest {

    @Test
    void theMetadataDescribesTheLimitWithItsDefaults() throws Exception {
        Map<String, JsonNode> properties = new HashMap<>();
        try (InputStream stream = getClass().getClassLoader()
                .getResourceAsStream("META-INF/additional-spring-configuration-metadata.json")) {
            assertThat(stream).isNotNull();
            new ObjectMapper().readTree(stream).get("properties")
                    .forEach(property -> properties.put(property.get("name").asText(), property));
        }

        JsonNode decisions = properties.get("contexa.security.zerotrust.analysis.new-context-limit.decisions");
        JsonNode window = properties.get("contexa.security.zerotrust.analysis.new-context-limit.window");

        assertThat(decisions).isNotNull();
        assertThat(decisions.get("type").asText()).isEqualTo("java.lang.Integer");
        assertThat(decisions.get("defaultValue").asInt()).isEqualTo(6);
        assertThat(decisions.get("description").asText()).contains("sign-in").contains("CHALLENGE");
        assertThat(window).isNotNull();
        assertThat(window.get("type").asText()).isEqualTo("java.time.Duration");
        assertThat(window.get("defaultValue").asText()).isEqualTo("1m");
    }
}
