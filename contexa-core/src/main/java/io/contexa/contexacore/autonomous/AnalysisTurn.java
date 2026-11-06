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
package io.contexa.contexacore.autonomous;

import java.util.Comparator;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Q-23 (PR-81): a piece of analysis work and its place in line. When the engine is behind, a session the model has not
 * decided yet goes before the sessions it has decided: filling the line with requests of others keeps no one away from
 * a first decision. Each kind keeps the order it came in, so no first decision is passed by a later one.
 */
public final class AnalysisTurn implements Runnable {

    /** On an event: its session has no decision of the model yet. */
    public static final String FIRST_DECISION = "analysisFirstDecision";

    /** The order of a line of analyses; work that knows no turn waits behind the turns. */
    public static final Comparator<Runnable> ORDER =
            Comparator.comparingInt(AnalysisTurn::lane).thenComparingLong(AnalysisTurn::arrival);

    private static final int FIRST_LANE = 0;
    private static final int OTHER_LANE = 1;
    private static final int NO_LANE = 2;
    private static final AtomicLong ARRIVALS = new AtomicLong();

    private final Runnable work;
    private final boolean firstDecision;
    private final long arrival = ARRIVALS.incrementAndGet();

    private AnalysisTurn(Runnable work, boolean firstDecision) {
        this.work = work;
        this.firstDecision = firstDecision;
    }

    public static AnalysisTurn of(Runnable work, boolean firstDecision) {
        return new AnalysisTurn(work, firstDecision);
    }

    /** Whether the work is the first decision of a session. */
    public static boolean isFirstDecision(Runnable work) {
        return work instanceof AnalysisTurn turn && turn.firstDecision;
    }

    @Override
    public void run() {
        work.run();
    }

    private static int lane(Runnable work) {
        if (work instanceof AnalysisTurn turn) {
            return turn.firstDecision ? FIRST_LANE : OTHER_LANE;
        }
        return NO_LANE;
    }

    private static long arrival(Runnable work) {
        return work instanceof AnalysisTurn turn ? turn.arrival : Long.MAX_VALUE;
    }
}
