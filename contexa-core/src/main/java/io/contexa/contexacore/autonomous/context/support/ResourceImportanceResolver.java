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

import io.contexa.contexacommon.annotation.ResourceImportance;
import org.springframework.lang.Nullable;

import java.util.Locale;
import java.util.Map;

/**
 * The one reading of a resource's importance (RL-14): what the host declared on the protected method together with
 * the sensitivity words the resource or the request carries. The reading only goes up. A resource declared sensitive
 * stays sensitive whatever a request states; one declared non-sensitive is raised to sensitive by a request that states
 * a sensitive or critical word; one that declares nothing is sensitive when such a word says so and otherwise stays
 * unspecified, as before. A word such as PUBLIC never turns an undeclared resource into a non-sensitive one: only the
 * host's own declaration does.
 */
public final class ResourceImportanceResolver {

    /** The key of the declared importance in the request's payload. */
    public static final String PAYLOAD_KEY = "resourceImportance";

    private ResourceImportanceResolver() {
    }

    /**
     * @param declared          the importance the host declared; null reads as unspecified
     * @param sensitivityValues the sensitivity words of the request or the resource, the first one that classifies wins
     */
    public static ResourceImportance resolve(@Nullable ResourceImportance declared, Object... sensitivityValues) {
        if (declared == ResourceImportance.SENSITIVE) {
            return ResourceImportance.SENSITIVE;
        }
        String level = sensitivityValues == null ? null : SecuritySemanticNormalizer.normalizeResourceClass(sensitivityValues);
        if ("SENSITIVE".equals(level) || "CRITICAL".equals(level)) {
            return ResourceImportance.SENSITIVE;
        }
        return declared == ResourceImportance.NON_SENSITIVE ? ResourceImportance.NON_SENSITIVE
                : ResourceImportance.UNSPECIFIED;
    }

    /** The importance of a request from its payload: the declared importance and the two sensitivity words. */
    public static ResourceImportance of(@Nullable Map<String, ?> payload) {
        if (payload == null) {
            return ResourceImportance.UNSPECIFIED;
        }
        return resolve(declaredIn(payload), payload.get("resourceSensitivity"), payload.get("sensitivity"));
    }

    /** The importance the host declared, as the payload carries it; unspecified for a value that names none. */
    public static ResourceImportance declaredIn(@Nullable Map<String, ?> payload) {
        Object value = payload != null ? payload.get(PAYLOAD_KEY) : null;
        if (value == null) {
            return ResourceImportance.UNSPECIFIED;
        }
        try {
            return ResourceImportance.valueOf(value.toString().trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException unknown) {
            return ResourceImportance.UNSPECIFIED;
        }
    }

    /** Whether the request is for a sensitive resource. */
    public static boolean sensitive(@Nullable Map<String, ?> payload) {
        return of(payload) == ResourceImportance.SENSITIVE;
    }

    /**
     * Whether the host declared the resource non-sensitive and nothing in the request raises it. Only such a resource
     * may be a candidate for a request that passes before the first verdict is in (RL-12).
     */
    public static boolean explicitlyNonSensitive(@Nullable Map<String, ?> payload) {
        return of(payload) == ResourceImportance.NON_SENSITIVE;
    }
}
