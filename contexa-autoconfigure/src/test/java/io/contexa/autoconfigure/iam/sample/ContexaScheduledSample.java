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
package io.contexa.autoconfigure.iam.sample;

import org.springframework.scheduling.annotation.Scheduled;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/** A class of the Contexa libraries with a schedule, written the way every one of them is. */
public class ContexaScheduledSample {

    public final BlockingQueue<String> threads = new LinkedBlockingQueue<>();

    @Scheduled(scheduler = "contexaTaskScheduler", fixedDelay = 20)
    public void tick() {
        threads.add(Thread.currentThread().getName());
    }
}
