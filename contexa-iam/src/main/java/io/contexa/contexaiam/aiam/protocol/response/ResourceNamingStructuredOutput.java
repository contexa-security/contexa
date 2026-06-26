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
package io.contexa.contexaiam.aiam.protocol.response;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class ResourceNamingStructuredOutput {

    private List<ResourceNamingSuggestionResponse.ResourceNamingSuggestion> suggestions;

    public ResourceNamingStructuredOutput(List<ResourceNamingSuggestionResponse.ResourceNamingSuggestion> suggestions) {
        this.suggestions = suggestions;
    }

    public List<ResourceNamingSuggestionResponse.ResourceNamingSuggestion> getSuggestions() {
        return suggestions != null ? suggestions : List.of();
    }

    public ResourceNamingSuggestionResponse toSuggestionResponse() {
        return new ResourceNamingSuggestionResponse(getSuggestions(), List.of());
    }
}
