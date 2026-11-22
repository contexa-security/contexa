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
package io.contexa.contexacore.autonomous.baseline;

import io.contexa.contexacommon.security.baseline.BaselineVector;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The baselines a decision read when it drew its prompt, fixed at that moment: the person's and the organization's,
 * each null when the decision found none. Both are copies taken when they were read, so nothing the baseline store
 * learns afterwards, this decision's own learning included, is in them. The sealed evidence capture keeps them with
 * the decision, and a replay draws the decision again against them.
 *
 * @param personal     the person's baseline as the decision read it, or null when there was none
 * @param organization the organization's baseline as the decision read it, or null when there was none
 */
public record DecisionBaselines(BaselineVector personal, BaselineVector organization) {

    /**
     * The baselines as they are read now: a copy of each, made on the calling thread. A store may hand out the object
     * it keeps (the in-memory store does), and the capture seals after the decision is enforced, so the values are
     * fixed here. The copy is a few arrays and maps of the baseline's size, no serialization.
     */
    public static DecisionBaselines readNow(BaselineVector personal, BaselineVector organization) {
        return new DecisionBaselines(copyOf(personal), copyOf(organization));
    }

    /** A copy that shares no array, map or set with the baseline read; null for none. */
    static BaselineVector copyOf(BaselineVector read) {
        if (read == null) {
            return null;
        }
        return BaselineVector.builder()
                .userId(read.getUserId())
                .normalIpRanges(copy(read.getNormalIpRanges()))
                .normalAccessHours(copy(read.getNormalAccessHours()))
                .normalAccessDays(copy(read.getNormalAccessDays()))
                .frequentPaths(copy(read.getFrequentPaths()))
                .normalUserAgents(copy(read.getNormalUserAgents()))
                .normalOperatingSystems(copy(read.getNormalOperatingSystems()))
                .normalBrowsers(copy(read.getNormalBrowsers()))
                .normalDevices(copy(read.getNormalDevices()))
                .normalIpBands(copy(read.getNormalIpBands()))
                .normalAuthenticationTypes(copy(read.getNormalAuthenticationTypes()))
                .frequentActionFamilies(copy(read.getFrequentActionFamilies()))
                .frequentResourceFamilies(copy(read.getFrequentResourceFamilies()))
                .vocabularyVersion(read.getVocabularyVersion())
                .learnedDates(copy(read.getLearnedDates()))
                .recentNovelty(read.getRecentNovelty())
                .updateCount(read.getUpdateCount())
                .elementFrequencies(copy(read.getElementFrequencies()))
                .elementLastSeen(copy(read.getElementLastSeen()))
                .verifiedElements(copy(read.getVerifiedElements()))
                .learnedMembers(copy(read.getLearnedMembers()))
                .lastUpdated(read.getLastUpdated())
                .avgRequestCount(read.getAvgRequestCount())
                .avgTrustScore(read.getAvgTrustScore())
                .build();
    }

    private static String[] copy(String[] values) {
        return values == null ? null : values.clone();
    }

    private static Integer[] copy(Integer[] values) {
        return values == null ? null : values.clone();
    }

    private static Map<String, Long> copy(Map<String, Long> values) {
        return values == null ? null : new HashMap<>(values);
    }

    private static Set<String> copy(Set<String> values) {
        return values == null ? null : new HashSet<>(values);
    }
}
