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
package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/** PR-73: the topics made at start are the ones the publisher writes to and the collector reads. */
class SecurityEventTopicsTest {

    @Test
    void theNameIsTheCategoryAndTheTypeInLowerCase() {
        assertThat(SecurityEventTopics.of(ZeroTrustEventCategory.AUTHENTICATION, "SUCCESS"))
                .isEqualTo("security.events.authentication.success");
        assertThat(SecurityEventTopics.of(ZeroTrustEventCategory.CUSTOM, "Order-Placed"))
                .isEqualTo("security.events.custom.order-placed");
    }

    @Test
    void everyTypeTheEventDeclaresHasItsTopicMadeAtStart() throws Exception {
        List<String> declared = new ArrayList<>();
        for (Field field : ZeroTrustSpringEvent.class.getFields()) {
            if (Modifier.isStatic(field.getModifiers()) && field.getName().startsWith("TYPE_")) {
                String[] name = field.getName().split("_");
                declared.add(SecurityEventTopics.of(ZeroTrustEventCategory.valueOf(name[1].toUpperCase(Locale.ROOT)),
                        (String) field.get(null)));
            }
        }

        assertThat(declared).isNotEmpty();
        assertThat(SecurityEventTopics.DECLARED).containsExactlyInAnyOrderElementsOf(declared);
    }

    @Test
    void theCollectorsPatternReadsEveryDeclaredTopicAndATypeOfTheApplications() {
        Pattern pattern = Pattern.compile(SecurityEventTopics.PATTERN);

        assertThat(SecurityEventTopics.DECLARED).allMatch(topic -> pattern.matcher(topic).matches());
        assertThat(pattern.matcher(SecurityEventTopics.of(ZeroTrustEventCategory.CUSTOM, "SOMETHING_ELSE")).matches())
                .isTrue();
        assertThat(pattern.matcher("security-events").matches()).as("the general topic is another topic").isFalse();
    }
}
