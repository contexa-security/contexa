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
package io.contexa.contexacore.std.llm.gate;

import java.util.concurrent.Callable;

/**
 * Marks the thread of a model call Contexa makes (a chat call of its LLM orchestrator, an embedding through its gate).
 * A model client's own retry can tell such a call from one the application makes itself, and stop at once for a server
 * that cannot be reached ({@link UnreachableModelServerRetryListener}): Contexa decides on retrying its calls.
 */
public final class ModelCallScope {

    private static final ThreadLocal<Boolean> ACTIVE = new ThreadLocal<>();

    private ModelCallScope() {
    }

    /** Whether the current thread runs a model call of Contexa. */
    public static boolean active() {
        return Boolean.TRUE.equals(ACTIVE.get());
    }

    /** Runs the call as a model call of Contexa; a call already inside one keeps it. */
    public static <T> T call(Callable<T> call) throws Exception {
        if (active()) {
            return call.call();
        }
        ACTIVE.set(Boolean.TRUE);
        try {
            return call.call();
        } finally {
            ACTIVE.remove();
        }
    }
}
