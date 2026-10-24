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

import java.time.LocalDateTime;
import java.util.Collection;
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

    /**
     * W6-12: the conditions the store chooses the scope's records by, in words, for the seal; none when it cannot say.
     */
    default List<String> filters() {
        return List.of();
    }

    /** W6-12: the order the store shows the records in, in words, for the seal; none when it cannot say. */
    default List<String> order() {
        return List.of();
    }

    /**
     * The user's recent decisions that did not allow (W5-4): the suspicious, threat and ambiguous records of the scope's
     * user, purpose and action family made since the time, outside the excluded sessions, the latest first, at most the
     * limit. A store without exact lookups has none.
     */
    default List<Document> deniedDecisions(PastRecordScope scope, LocalDateTime since, int limit) {
        return List.of();
    }

    /**
     * Writes how a decision that did not allow ended (verified by step-up, released by an administrator) on its record
     * (W5-4); false when the store cannot or the record is not there.
     */
    default boolean recordOutcome(String documentId, String outcome) {
        return false;
    }

    /**
     * docs/agent A3-8: quarantines the records of an agent, of one of its delegations when a delegation id is given; the
     * number of records changed. A quarantined record is never read.
     */
    default int quarantineAgentRecords(String agentId, String delegationId) {
        return 0;
    }

    /**
     * docs/agent A3-8: releases the quarantined records of an agent, of one of its delegations when one is given, and
     * gives them back the learning state they had; the records of the delegations still quarantined stay quarantined.
     * The number of records changed.
     */
    default int releaseAgentRecords(String agentId, String delegationId, Collection<String> quarantinedDelegations) {
        return 0;
    }

    /** docs/agent A3-8: removes the records of an agent, of one of its delegations when one is given; the number. */
    default int removeAgentRecords(String agentId, String delegationId) {
        return 0;
    }

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
