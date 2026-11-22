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
package io.contexa.contexaiam.admin.promptquality.measure;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The line the work that decides sealed decisions or labelled cases again waits in on this server (quality plan 3.3):
 * the trials of prompt versions and the measurements of the prompt quality run one after the other on one thread, and
 * their model calls wait behind the decisions at the model server's gate.
 */
public class PromptQualityRunLine implements AutoCloseable {

    /** The name of the line's thread. */
    public static final String THREAD_NAME = "contexa-prompt-version-trial";

    private final ExecutorService executor;

    public PromptQualityRunLine() {
        this(Executors.newSingleThreadExecutor(work -> {
            Thread thread = new Thread(work, THREAD_NAME);
            thread.setDaemon(true);
            return thread;
        }));
    }

    public PromptQualityRunLine(ExecutorService executor) {
        this.executor = executor;
    }

    /** The executor of the line, one thread. */
    public ExecutorService executor() {
        return executor;
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }
}
