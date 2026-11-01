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

import io.micrometer.core.instrument.FunctionCounter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;

/**
 * Publishes {@link UnifiedVectorService#storeFailureStats()} to a Micrometer registry (BR-C4, QF-8):
 * {@code contexa.vector.store.failed}, {@code .pending}, {@code .retried}, {@code .dropped} and {@code .deferred}
 * (QF-25 b). The vector store auto-configuration binds it to the application's registry where Micrometer and a registry
 * exist; the engine does not need Micrometer to run.
 */
public class StoreFailureMetrics implements MeterBinder {

    public static final String FAILED = "contexa.vector.store.failed";
    public static final String PENDING = "contexa.vector.store.pending";
    public static final String RETRIED = "contexa.vector.store.retried";
    public static final String DROPPED = "contexa.vector.store.dropped";
    public static final String DEFERRED = "contexa.vector.store.deferred";

    private final UnifiedVectorService vectorService;

    public StoreFailureMetrics(UnifiedVectorService vectorService) {
        this.vectorService = vectorService;
    }

    @Override
    public void bindTo(MeterRegistry registry) {
        // The registry holds the service weakly, so it is the service bean itself that is given, not a lambda.
        FunctionCounter.builder(FAILED, vectorService, service -> service.storeFailureStats().failed())
                .description("Documents whose vector store failed and were taken in for a retry")
                .register(registry);
        Gauge.builder(PENDING, vectorService, service -> service.storeFailureStats().pending())
                .description("Documents that wait for a vector store retry")
                .register(registry);
        FunctionCounter.builder(RETRIED, vectorService, service -> service.storeFailureStats().retried())
                .description("Documents stored by a vector store retry")
                .register(registry);
        FunctionCounter.builder(DROPPED, vectorService, service -> service.storeFailureStats().dropped())
                .description("Documents given up or pushed out of the full retry queue")
                .register(registry);
        FunctionCounter.builder(DEFERRED, vectorService, service -> service.storeFailureStats().deferred())
                .description("Documents left to the vector store retry without a store attempt because the learning "
                        + "executor had no room for their store")
                .register(registry);
    }
}
