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
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

/**
 * A vector store in memory whose adds can be made to fail, like an embedding server that is switched off. An add
 * writes its rows by id and overwrites a row of the same id, as the pgvector store does with
 * {@code ON CONFLICT (id) DO UPDATE} (spring-ai-pgvector-store 1.1.8, PgVectorStore.insertOrUpdateBatch).
 */
final class FlakyVectorStore implements VectorStore {

    private final Map<String, Document> rows = new ConcurrentHashMap<>();
    private final AtomicInteger addCalls = new AtomicInteger();
    private final AtomicInteger failuresLeft = new AtomicInteger();
    private final List<List<String>> addedBatches = new ArrayList<>();
    private volatile boolean down;
    private volatile Predicate<List<Document>> rejects = batch -> false;
    private volatile Runnable duringAdd = () -> { };
    private volatile String failure = "Connection refused: no embedding server";

    /** The next adds fail, this many of them, then the store works again. */
    FlakyVectorStore failNext(int adds) {
        failuresLeft.set(adds);
        return this;
    }

    /** Every add fails until {@link #recover()}. */
    FlakyVectorStore goDown() {
        down = true;
        return this;
    }

    FlakyVectorStore recover() {
        down = false;
        failuresLeft.set(0);
        rejects = batch -> false;
        return this;
    }

    /** An add of a batch the condition accepts fails, whatever else the store is doing. */
    FlakyVectorStore rejecting(Predicate<List<Document>> condition) {
        this.rejects = condition;
        return this;
    }

    /** What the store throws while it fails. */
    FlakyVectorStore failingWith(String message) {
        this.failure = message;
        return this;
    }

    /** Runs the action inside every add that is accepted, before its rows are written. */
    FlakyVectorStore doingDuringAdd(Runnable action) {
        this.duringAdd = action;
        return this;
    }

    Map<String, Document> rows() {
        return rows;
    }

    int addCalls() {
        return addCalls.get();
    }

    synchronized List<List<String>> addedBatches() {
        return new ArrayList<>(addedBatches);
    }

    @Override
    public void add(List<Document> documents) {
        addCalls.incrementAndGet();
        synchronized (this) {
            addedBatches.add(documents.stream().map(Document::getId).toList());
        }
        if (down || failuresLeft.getAndUpdate(left -> Math.max(0, left - 1)) > 0 || rejects.test(documents)) {
            throw new RuntimeException(failure);
        }
        duringAdd.run();
        documents.forEach(document -> rows.put(document.getId(), document));
    }

    @Override
    public void delete(List<String> idList) {
        idList.forEach(rows::remove);
    }

    @Override
    public void delete(Filter.Expression filterExpression) {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<Document> similaritySearch(SearchRequest request) {
        return List.of();
    }
}
