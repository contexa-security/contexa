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
package io.contexa.contexacore.autonomous.tiered.prompt;

import org.springframework.ai.document.Document;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * v1.0 (D3, from v19 A14 and B7): the similar cases a v1.0 bundle with the similarity search adds to the exact past
 * record lookup. The similarity search's documents carry a mark; the PAST RECORDS lines, counts and state stay the exact
 * lookup's, and the marked documents are drawn apart as SimilarCase lines.
 */
public final class SimilarCases {

    /** The document metadata that marks a similar case of the similarity search. */
    public static final String MARK = "v1SimilarCase";
    /** Where a sealed package keeps the similar cases, apart from its past records ({@code ragResultsJson}). */
    public static final String SEALED_KEY = "similarCases";

    private SimilarCases() {
    }

    /** The exact lookup's documents, then the similar cases it did not find, each marked. */
    public static List<Document> join(List<Document> exact, List<Document> similar) {
        List<Document> joined = new ArrayList<>(exact != null ? exact : List.of());
        if (similar == null || similar.isEmpty()) {
            return joined;
        }
        Set<String> exactIds = new HashSet<>();
        joined.stream().map(Document::getId).filter(Objects::nonNull).forEach(exactIds::add);
        for (Document document : similar) {
            if (document == null || (document.getId() != null && exactIds.contains(document.getId()))) {
                continue;
            }
            joined.add(marked(document));
        }
        return joined;
    }

    /** Whether the document is a similar case, not a record of the exact lookup. */
    public static boolean isSimilarCase(Document document) {
        return document != null && document.getMetadata() != null
                && Boolean.TRUE.equals(document.getMetadata().get(MARK));
    }

    /** The documents of the exact lookup only. */
    public static List<Document> exact(List<Document> documents) {
        return documents == null ? List.of() : documents.stream().filter(document -> !isSimilarCase(document)).toList();
    }

    /** The similar cases only. */
    public static List<Document> similar(List<Document> documents) {
        return documents == null ? List.of() : documents.stream().filter(SimilarCases::isSimilarCase).toList();
    }

    private static Document marked(Document document) {
        Map<String, Object> metadata = new LinkedHashMap<>(document.getMetadata() != null ? document.getMetadata() : Map.of());
        metadata.put(MARK, true);
        return Document.builder()
                .id(document.getId())
                .text(document.getText())
                .metadata(metadata)
                .score(document.getScore())
                .build();
    }
}
