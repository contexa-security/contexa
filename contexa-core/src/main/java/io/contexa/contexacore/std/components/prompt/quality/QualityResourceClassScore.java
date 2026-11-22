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

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * The metrics of a measurement over the cases of one resource class (quality P46). A class no case has is shown all
 * the same, without a score: an average over every class would hide a version that is worse on a sensitive resource
 * alone, and a class with nothing to measure says so rather than taking another class's numbers.
 *
 * @param resourceClass the class, or {@link QualityCaseResource#UNCLASSIFIED}
 * @param cases         the cases of the class
 * @param stopRoots     the distinct roots of the cases of the class that must be stopped
 * @param allowRoots    the distinct roots of the cases of the class that must be allowed
 * @param score         the metrics over the cases of the class, each with its count, sample and 95% interval over
 *                      the roots; null when no case has the class
 */
public record QualityResourceClassScore(String resourceClass, int cases, int stopRoots, int allowRoots,
                                        QualityScore score) {

    static QualityResourceClassScore of(String resourceClass, Collection<QualityCase> members, QualityScore score) {
        int[] roots = roots(members);
        return new QualityResourceClassScore(resourceClass, members.size(), roots[0], roots[1], score);
    }

    /** Whether the class has a case to score. */
    public boolean scored() {
        return score != null;
    }

    /** The distinct roots of the cases that must be stopped and of those that must be allowed. */
    static int[] roots(Collection<QualityCase> members) {
        Set<String> stop = new HashSet<>();
        Set<String> allow = new HashSet<>();
        for (QualityCase item : members) {
            (item.shouldStop() ? stop : allow).add(item.rootKey());
        }
        return new int[] {stop.size(), allow.size()};
    }
}
