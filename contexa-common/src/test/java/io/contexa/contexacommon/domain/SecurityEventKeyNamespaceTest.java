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
package io.contexa.contexacommon.domain;

import io.contexa.contexacommon.store.ApplicationNamespace;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** The keys an event names for its user context and its session are the key they always were, behind the name of the application. */
class SecurityEventKeyNamespaceTest {

    private static SecurityEvent event() {
        SecurityEvent event = new SecurityEvent();
        event.setUserId("alice");
        event.setSessionId("session-1");
        return event;
    }

    @Test
    @DisplayName("an application without a name keeps the keys")
    void unnamed() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
            assertThat(event().getUserContextKey()).isEqualTo("security:user:context:alice");
            assertThat(event().getSessionMappingKey()).isEqualTo("security:session:user:session-1");
        }
    }

    @Test
    @DisplayName("an application with a name puts ctxa:<name>: before them")
    void named() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            assertThat(event().getUserContextKey()).isEqualTo("ctxa:shop:security:user:context:alice");
            assertThat(event().getSessionMappingKey()).isEqualTo("ctxa:shop:security:session:user:session-1");
        }
    }
}
