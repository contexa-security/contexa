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

import java.util.List;

/**
 * The past records of a request by an exact metadata lookup (W3-18), not by a similarity search: a similarity between
 * records of the same work tells nothing (deep investigation R1), and the facts a decision needs are counts and times.
 */
public interface PastRecordQuery {

    /** Whether the store can answer exact lookups. */
    boolean available();

    /** The records of the scope, counted by path template, path and HTTP method. */
    List<PastRecordGroup> groups(PastRecordScope scope);

    /**
     * Records of the scope to show: those of the first paths first, then the latest, then the stored ID; at most the
     * limit.
     */
    List<Document> records(PastRecordScope scope, List<String> firstPaths, int limit);

    /** A query for a store that cannot answer exact lookups. */
    static PastRecordQuery unavailable() {
        return Unavailable.INSTANCE;
    }

    /** The query of a store without exact lookups. */
    enum Unavailable implements PastRecordQuery {
        INSTANCE;

        @Override
        public boolean available() {
            return false;
        }

        @Override
        public List<PastRecordGroup> groups(PastRecordScope scope) {
            return List.of();
        }

        @Override
        public List<Document> records(PastRecordScope scope, List<String> firstPaths, int limit) {
            return List.of();
        }
    }
}
