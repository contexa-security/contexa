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
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The baselines a decision read are fixed when they are read: a copy of every value that shares nothing with the
 * baseline the store handed out, so what the store learns afterwards is not in what the sealed evidence keeps.
 */
class DecisionBaselinesTest {

    @Test
    void aCopyHoldsEveryValueAndSharesNothingWithTheBaselineRead() throws Exception {
        BaselineVector read = everyValueSet();
        // Every field of the baseline is set here, so a field added later without its copy fails below.
        for (Field field : values()) {
            assertThat(field.get(read)).as("the test sets %s", field.getName()).isNotNull();
        }

        DecisionBaselines kept = DecisionBaselines.readNow(read, null);

        assertThat(kept.organization()).isNull();
        assertThat(kept.personal()).isNotSameAs(read).isEqualTo(read);
        for (Field field : values()) {
            Object original = field.get(read);
            Object copied = field.get(kept.personal());
            assertThat(copied).as("%s is copied", field.getName()).isNotNull();
            if (original.getClass().isArray() || original instanceof Map || original instanceof Collection) {
                assertThat(copied).as("%s is not shared", field.getName()).isNotSameAs(original);
            }
        }
    }

    @Test
    void whatTheStoreLearnsAfterwardsIsNotInWhatWasRead() {
        BaselineVector personal = everyValueSet();
        BaselineVector organization = everyValueSet();
        organization.setUserId("org:org-a");

        DecisionBaselines kept = DecisionBaselines.readNow(personal, organization);
        // The in-memory store hands out the object it keeps; a learning after the decision changes it in place.
        personal.getNormalIpRanges()[0] = "203.0.113.0/24";
        personal.getNormalAccessHours()[0] = 3;
        personal.getElementFrequencies().put("ip:203.0.113.0/24", 1L);
        personal.getElementLastSeen().clear();
        personal.getVerifiedElements().add("ip:203.0.113.0/24");
        personal.setUpdateCount(26L);
        organization.getLearnedMembers().add("member-2");

        assertThat(kept.personal().getNormalIpRanges()).containsExactly("10.1.0.0/16");
        assertThat(kept.personal().getNormalAccessHours()).containsExactly(9, 10);
        assertThat(kept.personal().getElementFrequencies()).containsOnlyKeys("ip:10.1.0.0/16");
        assertThat(kept.personal().getElementLastSeen()).containsOnlyKeys("ip:10.1.0.0/16");
        assertThat(kept.personal().getVerifiedElements()).containsExactly("ip:10.1.0.0/16");
        assertThat(kept.personal().getUpdateCount()).isEqualTo(25L);
        assertThat(kept.organization().getUserId()).isEqualTo("org:org-a");
        assertThat(kept.organization().getLearnedMembers()).containsExactly("member-1");
    }

    /** No baseline stays none: a decision that found no baseline says so, it does not get an empty one. */
    @Test
    void noBaselineStaysNone() {
        DecisionBaselines kept = DecisionBaselines.readNow(null, null);

        assertThat(kept.personal()).isNull();
        assertThat(kept.organization()).isNull();
    }

    /** A baseline stored before a value was kept has it null; the copy keeps it null. */
    @Test
    void aValueTheBaselineDoesNotHaveStaysNull() {
        BaselineVector earlier = new BaselineVector();
        earlier.setUserId("alice");
        earlier.setElementLastSeen(null);
        earlier.setVerifiedElements(null);

        BaselineVector copied = DecisionBaselines.readNow(earlier, null).personal();

        assertThat(copied).isEqualTo(earlier);
        assertThat(copied.getNormalIpRanges()).isNull();
        assertThat(copied.getElementLastSeen()).isNull();
        assertThat(copied.getVerifiedElements()).isNull();
    }

    private static List<Field> values() {
        List<Field> fields = new ArrayList<>();
        for (Field field : BaselineVector.class.getDeclaredFields()) {
            if (!Modifier.isStatic(field.getModifiers()) && !field.isSynthetic()) {
                field.setAccessible(true);
                fields.add(field);
            }
        }
        return fields;
    }

    private static BaselineVector everyValueSet() {
        return BaselineVector.builder()
                .userId("tenant-a::alice")
                .normalIpRanges(new String[]{"10.1.0.0/16"})
                .normalAccessHours(new Integer[]{9, 10})
                .normalAccessDays(new Integer[]{1, 2})
                .frequentPaths(new String[]{"/api/orders"})
                .normalUserAgents(new String[]{"Chrome/140"})
                .normalOperatingSystems(new String[]{"WINDOWS"})
                .normalBrowsers(new String[]{"Chrome"})
                .normalDevices(new String[]{"Chrome/140 on WINDOWS"})
                .normalIpBands(new String[]{"10.1.0.0/16"})
                .normalAuthenticationTypes(new String[]{"password"})
                .frequentActionFamilies(new String[]{"READ"})
                .frequentResourceFamilies(new String[]{"ORDER"})
                .vocabularyVersion("v1")
                .learnedDates(new String[]{"2026-11-21"})
                .recentNovelty("0010")
                .updateCount(25L)
                .elementFrequencies(new HashMap<>(Map.of("ip:10.1.0.0/16", 25L)))
                .elementLastSeen(new HashMap<>(Map.of("ip:10.1.0.0/16", 1_795_000_000_000L)))
                .verifiedElements(new HashSet<>(List.of("ip:10.1.0.0/16")))
                .learnedMembers(new HashSet<>(List.of("member-1")))
                .lastUpdated(Instant.parse("2026-11-21T08:00:00Z"))
                .avgRequestCount(12L)
                .avgTrustScore(0.8d)
                .build();
    }
}
