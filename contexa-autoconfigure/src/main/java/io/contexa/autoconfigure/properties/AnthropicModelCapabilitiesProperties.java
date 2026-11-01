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

import io.contexa.contexacore.std.llm.client.AnthropicThinkingCapability;
import io.contexa.contexacore.std.llm.client.ProviderAwareChatOptionsFactory;
import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** What Contexa adjusts on an Anthropic chat model for the Claude models it runs. */
@Data
@ConfigurationProperties(prefix = AnthropicModelCapabilitiesProperties.PREFIX)
public class AnthropicModelCapabilitiesProperties {

    public static final String PREFIX = "contexa.llm.model-capabilities.anthropic";

    /** The Claude models that refuse any sampling value but the default (regular expressions, comma separated). */
    private String defaultSamplingOnlyPatterns = ProviderAwareChatOptionsFactory.ANTHROPIC_DEFAULT_SAMPLING_ONLY_PATTERNS;

    /**
     * What each Claude model takes of thinking and effort, read top down; the first row whose pattern matches the whole
     * model id applies. The default rows are the Claude API's tables as read on 2026-10-30
     * (https://platform.claude.com/docs/en/build-with-claude/thinking-troubleshooting and .../effort); a list set here
     * replaces them. A model no row names gets what its layer asks, and a 400 for a field it refuses is sent once more
     * without that field.
     */
    private List<AnthropicThinkingCapability> thinking = new ArrayList<>(AnthropicThinkingCapability.officialTable());

    /**
     * Whether the system prompt is cached when no cache strategy is configured: Anthropic caches only what a request
     * marks, where OpenAI caches a repeated prompt by itself.
     */
    private boolean systemPromptCache = true;
}
