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
package io.contexa.contexacore.std.components.prompt.quality;

import java.util.List;

/**
 * The cases two versions answer differently (plan 3.4), among the cases both measurements scored. A case counts as
 * missed, or stopped, by a version when that happened in at least one of its runs.
 *
 * @param newlyMissed   cases that must be stopped: the version in use never allowed, the candidate did
 * @param newlyCaught   cases that must be stopped: the version in use allowed, the candidate never did
 * @param newlyStopped  cases that must be allowed: the version in use always allowed, the candidate did not
 * @param newlyReleased cases that must be allowed: the version in use did not always allow, the candidate always did
 */
public record QualityCaseChanges(List<String> newlyMissed, List<String> newlyCaught, List<String> newlyStopped,
                                 List<String> newlyReleased) {

    public QualityCaseChanges {
        newlyMissed = List.copyOf(newlyMissed);
        newlyCaught = List.copyOf(newlyCaught);
        newlyStopped = List.copyOf(newlyStopped);
        newlyReleased = List.copyOf(newlyReleased);
    }

    /** No changed cases: the two versions were not compared. */
    public static QualityCaseChanges none() {
        return new QualityCaseChanges(List.of(), List.of(), List.of(), List.of());
    }
}
