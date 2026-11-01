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
package io.contexa.contexacore.autonomous.context.support;

import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.postretrieval.document.DocumentPostProcessor;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * BR-S4: the post-retrieval step of the past records behind Spring AI's {@link DocumentPostProcessor} contract. It
 * ranks the retrieved records by {@link PastRecordRanking} (similarity, then the latest, then the stored ID; the copies
 * of one record take one place) and, with a limit, keeps the first of them. The query is not read: the ranking keys
 * are the records' own. The vector search of the past records, the PAST RECORDS lines of a prompt and the prompt
 * inspector that redraws them all take the records through it, so they rank them the same way.
 */
public final class PastRecordPostProcessor implements DocumentPostProcessor {

    /** The query of a step that has no query text of its own (the records a prompt draws); the step does not read it. */
    public static final Query PAST_RECORDS = new Query("past records");

    private static final PastRecordPostProcessor RANKED = new PastRecordPostProcessor(-1);

    /** How many of the ranked records are kept; negative for all of them. */
    private final int limit;

    private PastRecordPostProcessor(int limit) {
        this.limit = limit;
    }

    /** Every record in ranking order. */
    public static PastRecordPostProcessor ranked() {
        return RANKED;
    }

    /** The first records of the ranking, at most the limit (none for a limit below one). */
    public static PastRecordPostProcessor top(int limit) {
        return new PastRecordPostProcessor(Math.max(0, limit));
    }

    /** The query of a search text, or {@link #PAST_RECORDS} when it has none (a Spring AI query needs a text). */
    public static Query queryOf(String text) {
        return StringUtils.hasText(text) ? new Query(text) : PAST_RECORDS;
    }

    @Override
    public List<Document> process(Query query, List<Document> documents) {
        return limit < 0 ? PastRecordRanking.ranked(documents) : PastRecordRanking.top(documents, limit);
    }
}
