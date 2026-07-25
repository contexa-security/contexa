/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 */
package io.contexa.autoconfigure.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = OpenAiModelCapabilitiesProperties.PREFIX)
public class OpenAiModelCapabilitiesProperties {

    public static final String PREFIX = "contexa.llm.model-capabilities.openai";
    public static final String DEFAULT_MAX_COMPLETION_TOKEN_PATTERNS =
            "gpt-5(?:[.-].*)?,o\\d+(?:[.-].*)?";
    public static final String DEFAULT_SAMPLING_ONLY_PATTERNS =
            DEFAULT_MAX_COMPLETION_TOKEN_PATTERNS;

    private String maxCompletionTokenPatterns = DEFAULT_MAX_COMPLETION_TOKEN_PATTERNS;
    private String defaultSamplingOnlyPatterns = DEFAULT_SAMPLING_ONLY_PATTERNS;
}
