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
package io.contexa.contexacore.autonomous.access;

import org.springframework.lang.Nullable;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * docs/agent B4: one access evaluation an enforcement point asks for, in the shape of the OpenID AuthZEN
 * Authorization API 1.0 (subject, action, resource, context). The enforcement point states the facts of the request it
 * received; Contexa decides on them.
 *
 * @param subject  who acts
 * @param action   what the subject does
 * @param resource what it acts on
 * @param context  the request's circumstances (empty for none)
 */
public record AccessEvaluationRequest(Subject subject, Action action, Resource resource, Map<String, Object> context) {

    public AccessEvaluationRequest {
        context = context != null ? Map.copyOf(withoutNulls(context)) : Map.of();
    }

    /**
     * The acting subject.
     *
     * @param type       {@code user}, {@code agent} or {@code service}
     * @param id         the subject's identifier, scoped to its type
     * @param properties more facts of the subject (empty for none)
     */
    public record Subject(String type, String id, Map<String, Object> properties) {
        public Subject {
            properties = properties != null ? Map.copyOf(withoutNulls(properties)) : Map.of();
        }
    }

    /**
     * @param name       the action's name, as the enforcement point names it
     * @param properties more facts of the action (empty for none)
     */
    public record Action(String name, Map<String, Object> properties) {
        public Action {
            properties = properties != null ? Map.copyOf(withoutNulls(properties)) : Map.of();
        }
    }

    /**
     * @param type       the resource's type
     * @param id         the resource's identifier, scoped to its type
     * @param properties more facts of the resource (empty for none)
     */
    public record Resource(String type, String id, Map<String, Object> properties) {
        public Resource {
            properties = properties != null ? Map.copyOf(withoutNulls(properties)) : Map.of();
        }
    }

    /** A text value of the map, or null. */
    @Nullable
    static String text(Map<String, Object> values, String key) {
        Object value = values.get(key);
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }

    private static Map<String, Object> withoutNulls(Map<String, Object> values) {
        Map<String, Object> kept = new LinkedHashMap<>();
        values.forEach((key, value) -> {
            if (key != null && value != null) {
                kept.put(key, value);
            }
        });
        return kept;
    }
}
