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
package io.contexa.contexacore.hcad.trigger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PendingAnomalyKeyFactoryTest {

    @Test
    @DisplayName("Base key must be actor-session scoped, not resource scoped")
    void baseKeyMustIgnoreMethodAndPath() {
        String base = PendingAnomalyKeyFactory.buildBaseKey("admin", "ctx-1");
        String users = PendingAnomalyKeyFactory.buildBaseKey("admin", "ctx-1", "GET", "/contexa/admin/users");
        String roles = PendingAnomalyKeyFactory.buildBaseKey("admin", "ctx-1", "POST", "/contexa/admin/roles");

        assertThat(users).isEqualTo(base);
        assertThat(roles).isEqualTo(base);
    }

    @Test
    @DisplayName("Different actor sessions must not share the same base key")
    void differentActorSessionsMustHaveDifferentBaseKeys() {
        String first = PendingAnomalyKeyFactory.buildBaseKey("admin", "ctx-1");
        String second = PendingAnomalyKeyFactory.buildBaseKey("admin", "ctx-2");

        assertThat(second).isNotEqualTo(first);
    }
}