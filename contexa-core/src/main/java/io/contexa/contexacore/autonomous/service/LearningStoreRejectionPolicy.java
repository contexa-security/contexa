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
package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.store.RequestPathScope;

import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * What the learning executor does with a task it has no room for (QF-25 b, R12). A {@link Deferrable} task, a decision
 * document store that the enforcement hands over while it holds the request's lock, is deferred: its document is left
 * to the vector store retry, so the enforcement thread does not wait for the embedding and the store and the document
 * is not lost. Every other task runs on the thread that handed it over, as {@link ThreadPoolExecutor.CallerRunsPolicy}
 * runs it, and is discarded once the executor is shut down. It runs there as Contexa's own work
 * ({@link RequestPathScope}): the thread may be serving a request, which must not wait for a store behind it.
 */
public final class LearningStoreRejectionPolicy implements RejectedExecutionHandler {

    /** A task that, when the executor has no room for it, can leave its work for later instead of running now. */
    public interface Deferrable extends Runnable {

        /** Leaves the work for later; it must not wait for the store. */
        void defer();
    }

    /** The task that runs the store, or defers it when the executor is saturated. */
    public static Deferrable deferrable(Runnable store, Runnable defer) {
        return new Deferrable() {
            @Override
            public void run() {
                store.run();
            }

            @Override
            public void defer() {
                defer.run();
            }
        };
    }

    @Override
    public void rejectedExecution(Runnable task, ThreadPoolExecutor executor) {
        if (task instanceof Deferrable deferrable) {
            deferrable.defer();
            return;
        }
        if (executor.isShutdown()) {
            return;
        }
        RequestPathScope.enter();
        try {
            task.run();
        } finally {
            RequestPathScope.leave();
        }
    }
}
