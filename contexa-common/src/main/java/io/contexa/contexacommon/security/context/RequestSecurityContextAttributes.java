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
package io.contexa.contexacommon.security.context;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

import java.util.List;

public final class RequestSecurityContextAttributes {

    private static final String CANONICAL_ATTRIBUTE_PREFIX = "ctxa.context.";

    private RequestSecurityContextAttributes() {
    }

    public enum Field {
        OBSERVED_AT("observedAt", List.of()),
        NEW_SESSION("isNewSession", List.of("isNewSession")),
        NEW_USER("isNewUser", List.of("isNewUser")),
        NEW_DEVICE("isNewDevice", List.of("isNewDevice")),
        BASELINE_CONFIDENCE("baselineConfidence", List.of("baselineConfidence")),
        SENSITIVE_RESOURCE("isSensitiveResource", List.of("isSensitiveResource")),
        RESOURCE_SENSITIVITY("resourceSensitivity", List.of("resourceSensitivity", "sensitivity")),
        RESOURCE_BUSINESS_LABEL(
                "resourceBusinessLabel",
                List.of("resourceBusinessLabel", "resourceLabel", "businessLabel")),
        RESOURCE_ID("resourceId", List.of("resourceId", "requestedResourceId", "protectedResourceId")),
        PREVIOUS_PATH("previousPath", List.of("previousPath")),
        LAST_REQUEST_INTERVAL_MS("lastRequestIntervalMs", List.of("lastRequestIntervalMs")),
        USER_ROLES("userRoles", List.of("userRoles")),
        GEO_LATITUDE("geoLatitude", List.of("geoLatitude", "latitude")),
        GEO_LONGITUDE("geoLongitude", List.of("geoLongitude", "longitude")),
        TRAVEL_DISTANCE_KM("travelDistanceKm", List.of("travelDistanceKm")),
        TRAVEL_ELAPSED_MINUTES("travelElapsedMinutes", List.of("travelElapsedMinutes")),
        PREVIOUS_LOCATION("previousLocation", List.of("previousLocation"));

        private final String canonicalAttributeKey;
        private final List<String> neutralAliases;

        Field(String canonicalName, List<String> neutralAliases) {
            this.canonicalAttributeKey = CANONICAL_ATTRIBUTE_PREFIX + canonicalName;
            this.neutralAliases = List.copyOf(neutralAliases);
        }

        public String canonicalAttributeKey() {
            return canonicalAttributeKey;
        }
    }

    public static Object read(HttpServletRequest request, Field field) {
        if (request == null || field == null) {
            return null;
        }
        Object canonical = materialValue(request.getAttribute(field.canonicalAttributeKey));
        if (canonical != null) {
            return canonical;
        }
        return firstMaterialValue(request, field.neutralAliases);
    }

    public static void write(
            HttpServletRequest request,
            Field field,
            Object value,
            boolean overwriteExisting
    ) {
        if (request == null || field == null || materialValue(value) == null) {
            return;
        }
        if (overwriteExisting || materialValue(request.getAttribute(field.canonicalAttributeKey)) == null) {
            request.setAttribute(field.canonicalAttributeKey, value);
        }
    }

    private static Object firstMaterialValue(HttpServletRequest request, List<String> attributeNames) {
        for (String attributeName : attributeNames) {
            Object value = materialValue(request.getAttribute(attributeName));
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private static Object materialValue(Object value) {
        if (value instanceof String text && !StringUtils.hasText(text)) {
            return null;
        }
        return value;
    }
}
