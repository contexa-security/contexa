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
package io.contexa.contexaiam.security.xacml.prp;

import java.util.concurrent.atomic.AtomicLong;

/**
 * A number that moves on each time this node reloads its policies: after a change of the policies on this node, and
 * after a change on another node in the distributed mode. What is worked out from all the policies and kept (the
 * dashboard's validation report) is worked out again once the number has moved.
 */
public final class PolicyGeneration {

    private static final AtomicLong GENERATION = new AtomicLong();

    private PolicyGeneration() {
    }

    public static long current() {
        return GENERATION.get();
    }

    public static void advance() {
        GENERATION.incrementAndGet();
    }
}
