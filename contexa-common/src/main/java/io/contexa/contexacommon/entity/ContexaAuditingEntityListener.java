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

import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sets the creation and modification times of Contexa's entities: the fields marked {@link CreatedDate} and
 * {@link LastModifiedDate}, as Spring Data's auditing does, but only for the entities that list this listener.
 * <p>
 * Contexa does not turn Spring Data auditing on ({@code @EnableJpaAuditing}): an application that has its own auditing
 * (its own {@code @EnableJpaAuditing} and {@code AuditorAware}) keeps it exactly as it is, and an application that has
 * entities with the annotations but never turned auditing on does not get it from Contexa.
 * <p>
 * On creation both times are set to now, on an update only the modification time, which is what the Spring Data listener
 * does with its default settings.
 */
public class ContexaAuditingEntityListener {

    private static final Map<Class<?>, Audited> FIELDS = new ConcurrentHashMap<>();

    @PrePersist
    public void touchForCreate(Object entity) {
        Audited audited = audited(entity.getClass());
        stamp(entity, audited.created());
        stamp(entity, audited.modified());
    }

    @PreUpdate
    public void touchForUpdate(Object entity) {
        stamp(entity, audited(entity.getClass()).modified());
    }

    private static void stamp(Object entity, List<Field> fields) {
        for (Field field : fields) {
            ReflectionUtils.setField(field, entity, now(field));
        }
    }

    private static Object now(Field field) {
        Class<?> type = field.getType();
        if (type == LocalDateTime.class) {
            return LocalDateTime.now();
        }
        if (type == Instant.class) {
            return Instant.now();
        }
        throw new IllegalStateException("Contexa's auditing sets LocalDateTime and Instant fields; "
                + field.getDeclaringClass().getName() + "." + field.getName() + " is a " + type.getName());
    }

    private static Audited audited(Class<?> type) {
        return FIELDS.computeIfAbsent(type, ContexaAuditingEntityListener::scan);
    }

    private static Audited scan(Class<?> type) {
        List<Field> created = new ArrayList<>();
        List<Field> modified = new ArrayList<>();
        for (Class<?> current = type; current != null && current != Object.class; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (field.isAnnotationPresent(CreatedDate.class)) {
                    ReflectionUtils.makeAccessible(field);
                    created.add(field);
                }
                if (field.isAnnotationPresent(LastModifiedDate.class)) {
                    ReflectionUtils.makeAccessible(field);
                    modified.add(field);
                }
            }
        }
        return new Audited(created, modified);
    }

    private record Audited(List<Field> created, List<Field> modified) {
    }
}
