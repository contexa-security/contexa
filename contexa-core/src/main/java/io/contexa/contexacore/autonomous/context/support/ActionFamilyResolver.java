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
package io.contexa.contexacore.autonomous.context.support;

import org.springframework.lang.Nullable;

import java.util.List;
import java.util.Map;

/**
 * The action family of a request from the facts of its event, in one order of sources: a value the host declared
 * first, then what the protected method's name says, then the fixed words of the protected URL template, then the HTTP
 * method. The result says which source decided it and its grade ({@code host} for a declared value,
 * {@code inferred} for the others), so that a family read from a method name is never shown as a declared one.
 */
public final class ActionFamilyResolver {

    public static final String HOST = "host";
    public static final String INFERRED = "inferred";

    private static final List<String> DECLARED_KEYS = List.of("actionFamily", "currentActionFamily", "operation");
    private static final String METHOD_KEY = "protectableMethod";
    private static final List<String> TEMPLATE_KEYS = List.of("protectableResourceUrl", "resourceUrlTemplate");
    private static final List<String> HTTP_METHOD_KEYS = List.of("httpMethod", "method");

    private ActionFamilyResolver() {
    }

    /**
     * @param family the family, UNKNOWN when no source names one
     * @param source {@code <grade>:<metadata key>} of the source that decided it, null for UNKNOWN
     */
    public record Resolution(ActionFamily family, @Nullable String source) {

        public String grade() {
            return source == null ? null : source.substring(0, source.indexOf(':'));
        }

        public String sourceKey() {
            return source == null ? null : source.substring(source.indexOf(':') + 1);
        }

        public boolean inferred() {
            return INFERRED.equals(grade());
        }
    }

    public static Resolution resolve(@Nullable Map<String, ?> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return new Resolution(ActionFamily.UNKNOWN, null);
        }
        for (String key : DECLARED_KEYS) {
            ActionFamily declared = ActionFamily.of(metadata.get(key));
            // A declared UNKNOWN states nothing; the other sources may still know the action.
            if (declared != null && declared != ActionFamily.UNKNOWN) {
                return new Resolution(declared, HOST + ":" + key);
            }
        }
        ActionFamily byMethod = ActionFamily.of(methodName(metadata.get(METHOD_KEY)));
        if (byMethod != null && byMethod != ActionFamily.UNKNOWN) {
            return new Resolution(byMethod, INFERRED + ":" + METHOD_KEY);
        }
        for (String key : TEMPLATE_KEYS) {
            ActionFamily byTemplate = ActionFamily.of(fixedWords(metadata.get(key)));
            if (byTemplate != null && byTemplate != ActionFamily.UNKNOWN) {
                return new Resolution(byTemplate, INFERRED + ":" + key);
            }
        }
        for (String key : HTTP_METHOD_KEYS) {
            ActionFamily byHttpMethod = ActionFamily.of(metadata.get(key));
            if (byHttpMethod != null && byHttpMethod != ActionFamily.UNKNOWN) {
                return new Resolution(byHttpMethod, INFERRED + ":" + key);
            }
        }
        return new Resolution(ActionFamily.UNKNOWN, null);
    }

    /** The method part of {@code package.Type.method} or {@code package.Type#method}. */
    @Nullable
    static String methodName(@Nullable Object qualifiedMethod) {
        if (qualifiedMethod == null) {
            return null;
        }
        String text = qualifiedMethod.toString().trim();
        int separator = Math.max(text.lastIndexOf('.'), text.lastIndexOf('#'));
        String name = separator >= 0 ? text.substring(separator + 1) : text;
        return name.isEmpty() ? null : name;
    }

    /** The template without its variable segments ({@code {projectKey}}), which name an instance, not an action. */
    @Nullable
    static String fixedWords(@Nullable Object template) {
        if (template == null) {
            return null;
        }
        String text = template.toString().replaceAll("\\{[^}]*}", " ").trim();
        return text.isEmpty() ? null : text;
    }
}
