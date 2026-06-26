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
package io.contexa.contexaiam.aiam.pipeline.processor;

import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.processor.DomainResponseProcessor;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingStructuredOutput;
import io.contexa.contexaiam.aiam.protocol.response.ResourceNamingSuggestionResponse;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@Slf4j
public class ResourceNamingResponseProcessor implements DomainResponseProcessor {

    @Override
    public boolean supports(String templateKey) {
        return "ResourceNaming".equals(templateKey);
    }

    @Override
    public boolean supportsType(Class<?> responseType) {
        return ResourceNamingStructuredOutput.class.equals(responseType)
                || ResourceNamingSuggestionResponse.class.equals(responseType);
    }

    @Override
    @SuppressWarnings("unchecked")
    public Object wrapResponse(Object parsedData, PipelineExecutionContext context) {
        if (parsedData instanceof ResourceNamingSuggestionResponse response) {
            return response;
        }
        if (parsedData instanceof ResourceNamingStructuredOutput output) {
            return output.toSuggestionResponse();
        }
        if (parsedData instanceof Map<?, ?> map) {
            return ResourceNamingSuggestionResponse.fromMap((Map<String, Object>) map);
        }
        throw new IllegalArgumentException(
                "Expected ResourceNamingStructuredOutput, ResourceNamingSuggestionResponse or Map but got: "
                        + (parsedData != null ? parsedData.getClass().getName() : "null")
        );
    }

    @Override
    public int getOrder() {
        return 20;
    }
}
