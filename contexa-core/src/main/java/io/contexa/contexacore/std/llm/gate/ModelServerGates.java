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

import io.contexa.contexacore.properties.ModelServerGateProperties;
import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The gates of the model servers the application calls, one per server (O-1). A call waits at its server's gate at most
 * until the event's deadline its {@link ModelCallTimer} carries, and without one at most the event budget.
 */
@Slf4j
public final class ModelServerGates {

    private final ModelServerResolver resolver;
    private final ModelServerGateProperties properties;
    private final long defaultMaxWaitMs;
    private final Map<String, ModelServerGate> gates = new ConcurrentHashMap<>();
    /** A call went to a server that passes no gate: what such a server serves is not known, so nothing is limited. */
    private volatile boolean ungatedCallSeen;

    /**
     * @param defaultMaxWaitMs the longest a call waits when no deadline bounds it: the event budget
     *                         ({@code contexa.security.plane.agent.event-timeout-ms})
     */
    public ModelServerGates(ModelServerResolver resolver, ModelServerGateProperties properties, long defaultMaxWaitMs) {
        this.resolver = resolver;
        this.properties = properties != null ? properties : new ModelServerGateProperties();
        this.defaultMaxWaitMs = Math.max(1L, defaultMaxWaitMs);
    }

    /** The gate of the server the model calls, or null when the gates are off or the server is not known. */
    public ModelServerGate gateFor(Object model, CallKind kind) {
        if (!properties.isEnabled() || model == null || resolver == null) {
            return null;
        }
        ModelServer server = resolver.resolve(model, kind);
        if (server == null) {
            ungatedCallSeen = true;
            return null;
        }
        return gates.computeIfAbsent(server.key(), key -> create(server));
    }

    /** The model an embedding model asks for, or a name that tells it from the chat models. */
    public String embeddingModelName(Object embeddingModel) {
        String name = resolver != null ? resolver.embeddingModelName(embeddingModel) : null;
        return name != null && !name.isBlank() ? name.trim() : CallKind.EMBEDDING.name();
    }

    /** The longest a call may wait now: until the timer's deadline, at most the event budget. */
    public long maxWaitMs(ModelCallTimer timer) {
        long deadline = timer != null ? timer.deadline() : 0L;
        if (deadline <= 0L) {
            return defaultMaxWaitMs;
        }
        return Math.max(0L, Math.min(defaultMaxWaitMs, deadline - System.currentTimeMillis()));
    }

    /**
     * Runs a call of the model through its server's gate, with the timer bound to this thread.
     *
     * @throws ModelServerBusyException when the call cannot get in in time
     */
    public <T> T call(Object model, CallKind kind, String modelName, Callable<T> call) throws Exception {
        ModelServerGate gate = gateFor(model, kind);
        if (gate == null) {
            return call.call();
        }
        ModelCallTimer timer = ModelCallTimer.current();
        try (ModelServerGate.Permit permit = gate.enter(kind, modelName, maxWaitMs(timer), timer)) {
            return permit.scope(call).call();
        }
    }

    /** Analyses per slot of a gate before the time of a chat call is known: the first wave of a burst. */
    private static final int FIRST_WAVE_PER_SLOT = 2;

    /**
     * How many analyses may run at once. A call waits at its server's gate at most until the event's budget, so the
     * analyses in flight must not outnumber what the narrowest chat gate serves within it. The analyses in line at a gate
     * take turns: each passes its chat calls (up to {@code chatCalls}) behind the calls of the others, so the last of
     * {@code n} analyses on {@code slots} slots is done after about {@code n / slots x chatCalls x callTime}, and that
     * must stay within the budget with {@code safety} to spare: {@code n = slots x budget / (chatCalls x callTime x
     * safety)}. The call time is the gate's own measure of a chat call. Never fewer than {@value #FIRST_WAVE_PER_SLOT}
     * analyses for each slot of the gate, so that the slots are not left idle while an analysis prepares its next call.
     * A gate that has taken no chat call, an embedding server, does not count: it says nothing about the analyses.
     * Before a chat call is measured (the first wave of a burst) each slot has {@value #FIRST_WAVE_PER_SLOT} analyses,
     * and before a chat server is known the narrowest configured limit holds, so that the first wave does not fill a gate
     * that turns out to be a narrow one. Where no gate limits (the gates are off, a server set to no limit, a call to a
     * server with no gate) nothing is limited.
     */
    public int analysisConcurrency(int chatCalls, double safety) {
        if (!properties.isEnabled() || resolver == null || ungatedCallSeen) {
            return Integer.MAX_VALUE;
        }
        long limit = Long.MAX_VALUE;
        boolean chatGateKnown = false;
        for (ModelServerGate gate : gates.values()) {
            if (!gate.chatCallsSeen()) {
                // an embedding server takes no chat call: it does not bound the analyses
                continue;
            }
            chatGateKnown = true;
            int slots = gate.maxConcurrent();
            if (slots <= 0) {
                continue;
            }
            long callMillis = gate.chatCallMillis();
            long forGate = callMillis <= 0L
                    ? (long) slots * FIRST_WAVE_PER_SLOT
                    : Math.max((long) slots * FIRST_WAVE_PER_SLOT, (long) (slots * (double) defaultMaxWaitMs
                    / (Math.max(1, chatCalls) * (double) callMillis * Math.max(1.0, safety))));
            limit = Math.min(limit, forGate);
        }
        if (!chatGateKnown) {
            int narrowest = narrowestOf(Integer.MAX_VALUE, properties.getSelfHostedMaxConcurrent());
            narrowest = narrowestOf(narrowest, properties.getRemoteMaxConcurrent());
            for (ModelServerGateProperties.Server server : properties.getServers().values()) {
                if (server != null && server.getMaxConcurrent() != null) {
                    narrowest = narrowestOf(narrowest, server.getMaxConcurrent());
                }
            }
            if (narrowest != Integer.MAX_VALUE) {
                limit = (long) narrowest * FIRST_WAVE_PER_SLOT;
            }
        }
        return limit == Long.MAX_VALUE ? Integer.MAX_VALUE : (int) Math.min(Integer.MAX_VALUE, limit);
    }

    /** The narrower of two limits, where 0 is no limit. */
    private static int narrowestOf(int current, int slots) {
        return slots > 0 ? Math.min(current, slots) : current;
    }

    private ModelServerGate create(ModelServer server) {
        ModelServerGateProperties.Server configured = properties.serverAt(server.address());
        int maxConcurrent = configured != null && configured.getMaxConcurrent() != null
                ? configured.getMaxConcurrent()
                : server.selfHosted() ? properties.getSelfHostedMaxConcurrent() : properties.getRemoteMaxConcurrent();
        boolean oneModelAtATime = configured != null && configured.getOneModelAtATime() != null
                ? configured.getOneModelAtATime()
                : server.selfHosted();
        log.info("[ModelServerGate] {}: {} call(s) at once{}", server.key(),
                maxConcurrent > 0 ? maxConcurrent : "unlimited",
                oneModelAtATime ? ", one model at a time" : "");
        return new ModelServerGate(server, maxConcurrent, oneModelAtATime,
                Duration.ofMillis(Math.max(0L, properties.getFirstBackOffMs())));
    }
}
