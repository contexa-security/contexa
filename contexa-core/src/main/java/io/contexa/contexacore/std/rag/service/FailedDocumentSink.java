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
package io.contexa.contexacore.std.rag.service;

import org.springframework.ai.document.Document;

import java.time.Instant;
import java.util.List;
import java.util.function.Predicate;

/**
 * Where the documents whose vector store failed wait for their retry (BR-C4, QF-8). The default,
 * {@link InMemoryFailedDocumentSink}, is a bounded queue in the memory of the process and loses what waits when the
 * process stops. An adopter whose records must outlive a restart provides its own bean of this type, for example one
 * that keeps the entries in an outbox table.
 * <p>
 * An entry is a document with a stable id, so that storing it again overwrites its row instead of adding a second one.
 * Implementations are used from the request threads (add, removeWhere) and from the single retry thread (the rest),
 * so they must be thread-safe.
 */
public interface FailedDocumentSink {

    /**
     * Adds the entries behind the ones that wait; an entry whose document id already waits replaces it. When the sink
     * is over its capacity the oldest entries are pushed out.
     *
     * @return the entries pushed out to keep within the capacity, oldest first; empty when none was
     */
    List<FailedDocument> add(List<FailedDocument> entries);

    /** The oldest entries, at most the number given. They stay in the sink until removed. */
    List<FailedDocument> oldest(int max);

    /**
     * Puts entries whose retry failed behind the others, with their new state. An entry that is no longer in the sink
     * (it was removed meanwhile) is not put back.
     */
    void requeue(List<FailedDocument> entries);

    /**
     * Removes the entries the condition accepts.
     *
     * @return the entries removed
     */
    List<FailedDocument> removeWhere(Predicate<FailedDocument> condition);

    /** How many entries wait. */
    int size();

    /**
     * A document that waits for its retry.
     *
     * @param document      the document as it was to be stored, with its stable id
     * @param firstFailedAt when its store first failed
     * @param attempts      how many retries have failed
     */
    record FailedDocument(Document document, Instant firstFailedAt, int attempts) {

        /** The id the document is stored under. */
        public String id() {
            return document.getId();
        }

        /** The same entry after one more failed retry. */
        public FailedDocument afterFailedAttempt() {
            return new FailedDocument(document, firstFailedAt, attempts + 1);
        }
    }
}
