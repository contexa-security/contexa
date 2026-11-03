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
package io.contexa.contexacommon.entity;

import org.junit.jupiter.api.Test;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import java.time.Instant;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContexaAuditingEntityListenerTest {

    private final ContexaAuditingEntityListener listener = new ContexaAuditingEntityListener();

    static class Base {
        @LastModifiedDate
        LocalDateTime updatedAt;
    }

    static class Entity extends Base {
        @CreatedDate
        LocalDateTime createdAt;
    }

    static class InstantEntity {
        @CreatedDate
        Instant observedAt;
    }

    static class UnsupportedEntity {
        @CreatedDate
        String createdAt;
    }

    @Test
    void creationSetsBothTimesIncludingTheOnesOfASuperclass() {
        Entity entity = new Entity();
        LocalDateTime before = LocalDateTime.now().minusSeconds(1);

        listener.touchForCreate(entity);

        assertThat(entity.createdAt).isAfter(before);
        assertThat(entity.updatedAt).isAfter(before);
    }

    @Test
    void creationReplacesATimeThatWasSetBefore() {
        Entity entity = new Entity();
        entity.createdAt = LocalDateTime.of(2000, 1, 1, 0, 0);

        listener.touchForCreate(entity);

        assertThat(entity.createdAt).isAfter(LocalDateTime.of(2020, 1, 1, 0, 0));
    }

    @Test
    void anUpdateTouchesOnlyTheModificationTime() {
        Entity entity = new Entity();
        LocalDateTime created = LocalDateTime.of(2000, 1, 1, 0, 0);
        entity.createdAt = created;

        listener.touchForUpdate(entity);

        assertThat(entity.createdAt).isEqualTo(created);
        assertThat(entity.updatedAt).isAfter(created);
    }

    @Test
    void anInstantFieldIsSetToo() {
        InstantEntity entity = new InstantEntity();

        listener.touchForCreate(entity);

        assertThat(entity.observedAt).isNotNull();
    }

    @Test
    void aFieldOfAnotherTypeFailsLoudlyInsteadOfStayingEmpty() {
        assertThatThrownBy(() -> listener.touchForCreate(new UnsupportedEntity()))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("UnsupportedEntity.createdAt");
    }

    @Test
    void anEntityWithoutTheAnnotationsIsLeftAlone() {
        Object plain = new Object();

        listener.touchForCreate(plain);
        listener.touchForUpdate(plain);
    }
}
