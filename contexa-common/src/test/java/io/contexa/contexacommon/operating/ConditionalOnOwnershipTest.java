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
package io.contexa.contexacommon.operating;

import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

class ConditionalOnOwnershipTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner().withUserConfiguration(Planes.class);

    @ParameterizedTest
    @ValueSource(strings = {"CONTEXA_OWNED", "contexa_owned", "contexa-owned", "contexaOwned"})
    void everySpellingTurnsOnTheWholePlane(String spelling) {
        runner.withPropertyValues("contexa.bridge.ownership=" + spelling).run(context -> {
            assertThat(context).hasBean("contexaPlane");
            assertThat(context).doesNotHaveBean("hostPlane");
        });
    }

    @Test
    void thePropertyConditionThisReplacesLeftHalfOfThePlaneOff() {
        runner.withPropertyValues("contexa.bridge.ownership=contexa-owned").run(context -> assertThat(context).doesNotHaveBean("byText"));
    }

    @Test
    void theOtherOwnershipTurnsOnTheOtherPlane() {
        runner.withPropertyValues("contexa.bridge.ownership=HOST_OWNED").run(context -> {
            assertThat(context).hasBean("hostPlane");
            assertThat(context).doesNotHaveBean("contexaPlane");
        });
    }

    @Test
    void whereNoOwnershipIsDeclaredOnlyAPlaneThatSaysSoIsOn() {
        runner.run(context -> {
            assertThat(context).doesNotHaveBean("hostPlane");
            assertThat(context).doesNotHaveBean("contexaPlane");
            assertThat(context).hasBean("undeclaredPlane");
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class Planes {

        @Bean
        @ConditionalOnOwnership(SecurityOwnershipMode.CONTEXA_OWNED)
        String contexaPlane() {
            return "contexa";
        }

        @Bean
        @ConditionalOnOwnership(SecurityOwnershipMode.HOST_OWNED)
        String hostPlane() {
            return "host";
        }

        @Bean
        @ConditionalOnOwnership(value = SecurityOwnershipMode.CONTEXA_OWNED, matchIfUndeclared = true)
        String undeclaredPlane() {
            return "undeclared";
        }

        @Bean
        @ConditionalOnProperty(prefix = "contexa.bridge", name = "ownership", havingValue = "CONTEXA_OWNED")
        String byText() {
            return "by text";
        }
    }
}
