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
package io.contexa.contexacore.std.security;

import org.springframework.ai.document.Document;

import java.util.List;
import java.util.Set;

public record AuthorizedPromptContext(
        List<Document> documents,
        int requestedDocumentCount,
        int allowedDocumentCount,
        int deniedDocumentCount,
        String retrievalPurpose,
        List<String> deniedReasons,
        PurposeBoundRetrievalPolicy retrievalPolicy,
        List<ContextProvenanceRecord> provenanceRecords,
        List<AuthorizedPromptContextItem> contextItems) {

    public AuthorizedPromptContext {
        documents = documents == null ? List.of() : List.copyOf(documents);
        deniedReasons = deniedReasons == null ? List.of() : List.copyOf(deniedReasons);
        retrievalPurpose = retrievalPurpose == null ? "general_context" : retrievalPurpose;
        retrievalPolicy = retrievalPolicy == null
                ? new PurposeBoundRetrievalPolicy(null, null, null, retrievalPurpose, Set.of())
                : retrievalPolicy;
        provenanceRecords = provenanceRecords == null ? List.of() : List.copyOf(provenanceRecords);
        contextItems = contextItems == null ? List.of() : List.copyOf(contextItems);
    }

    public AuthorizedPromptContext(
            List<Document> documents,
            int requestedDocumentCount,
            int allowedDocumentCount,
            int deniedDocumentCount,
            String retrievalPurpose,
            List<String> deniedReasons) {
        this(
                documents,
                requestedDocumentCount,
                allowedDocumentCount,
                deniedDocumentCount,
                retrievalPurpose,
                deniedReasons,
                new PurposeBoundRetrievalPolicy(null, null, null, retrievalPurpose, Set.of()),
                List.of(),
                List.of());
    }
}
