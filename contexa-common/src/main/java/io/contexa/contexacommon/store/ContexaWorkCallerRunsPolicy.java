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
package io.contexa.contexacommon.store;

import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Runs the work a full pool of Contexa's turned away on the thread that handed it over, as
 * {@link ThreadPoolExecutor.CallerRunsPolicy} runs it, and as Contexa's own work: when that thread is serving a request,
 * the work waits for a store no longer than Contexa's own work of a protected call does. Work handed over after the
 * executor was shut down is discarded.
 */
public final class ContexaWorkCallerRunsPolicy implements RejectedExecutionHandler {

    @Override
    public void rejectedExecution(Runnable work, ThreadPoolExecutor executor) {
        if (executor.isShutdown()) {
            return;
        }
        RequestPathScope.enter();
        try {
            work.run();
        } finally {
            RequestPathScope.leave();
        }
    }
}
