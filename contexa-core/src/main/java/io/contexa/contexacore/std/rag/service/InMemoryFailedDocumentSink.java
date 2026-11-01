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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * The default {@link FailedDocumentSink}: a bounded queue in the memory of the process (BR-C4, QF-8). When it is full
 * the oldest entry is pushed out. What waits in it is lost when the process stops.
 */
public class InMemoryFailedDocumentSink implements FailedDocumentSink {

    private final int capacity;
    /** The waiting entries by document id, in the order they wait. */
    private final Map<String, FailedDocument> entries = new LinkedHashMap<>();

    /** @param capacity the most entries that wait; below one it is one */
    public InMemoryFailedDocumentSink(int capacity) {
        this.capacity = Math.max(1, capacity);
    }

    @Override
    public synchronized List<FailedDocument> add(List<FailedDocument> added) {
        for (FailedDocument entry : added) {
            // A document that already waits keeps its place; the newer content replaces the older.
            entries.put(entry.id(), entry);
        }
        List<FailedDocument> pushedOut = new ArrayList<>();
        Iterator<FailedDocument> oldest = entries.values().iterator();
        while (entries.size() > capacity && oldest.hasNext()) {
            pushedOut.add(oldest.next());
            oldest.remove();
        }
        return pushedOut;
    }

    @Override
    public synchronized List<FailedDocument> oldest(int max) {
        List<FailedDocument> oldest = new ArrayList<>(Math.min(Math.max(0, max), entries.size()));
        for (FailedDocument entry : entries.values()) {
            if (oldest.size() >= max) {
                break;
            }
            oldest.add(entry);
        }
        return oldest;
    }

    @Override
    public synchronized void requeue(List<FailedDocument> requeued) {
        for (FailedDocument entry : requeued) {
            // Only an entry that still waits goes back, behind the others; one removed meanwhile stays removed.
            if (entries.remove(entry.id()) != null) {
                entries.put(entry.id(), entry);
            }
        }
    }

    @Override
    public synchronized List<FailedDocument> removeWhere(Predicate<FailedDocument> condition) {
        List<FailedDocument> removed = new ArrayList<>();
        Iterator<FailedDocument> waiting = entries.values().iterator();
        while (waiting.hasNext()) {
            FailedDocument entry = waiting.next();
            if (condition.test(entry)) {
                removed.add(entry);
                waiting.remove();
            }
        }
        return removed;
    }

    @Override
    public synchronized int size() {
        return entries.size();
    }
}
