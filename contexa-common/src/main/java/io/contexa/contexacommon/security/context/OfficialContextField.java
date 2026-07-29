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

import java.util.Locale;

public enum OfficialContextField {
    TENANT_ID(OfficialContextSlot.SECURITY_SCOPE, "tenantId"),
    ORGANIZATION_ID(OfficialContextSlot.SECURITY_SCOPE, "organizationId"),
    ORG_ID(OfficialContextSlot.SECURITY_SCOPE, "orgId"),
    MFA_VERIFIED(OfficialContextSlot.SESSION, "mfaVerified"),
    AUTHENTICATION_TYPE(OfficialContextSlot.SESSION, "authenticationType"),
    FAILED_LOGIN_ATTEMPTS(OfficialContextSlot.SESSION, "failedLoginAttempts"),
    RECENT_REQUEST_COUNT(OfficialContextSlot.SESSION, "recentRequestCount"),
    CURRENT_ACCESS_HOUR(OfficialContextSlot.SESSION, "currentAccessHour"),
    CONCURRENT_SESSIONS(OfficialContextSlot.SESSION, "concurrentSessions"),
    PASSWORD_AGE_DAYS(OfficialContextSlot.SESSION, "passwordAgeDays"),
    SESSION_AGE_MINUTES(OfficialContextSlot.SESSION, "sessionAgeMinutes"),
    COUNTRY(OfficialContextSlot.LOCATION, "country"),
    CITY(OfficialContextSlot.LOCATION, "city"),
    IP_BAND(OfficialContextSlot.LOCATION, "ipBand"),
    ASN(OfficialContextSlot.LOCATION, "asn"),
    DEVICE_OS(OfficialContextSlot.DEVICE, "deviceOs"),
    DEVICE_OS_VERSION(OfficialContextSlot.DEVICE, "deviceOsVersion"),
    DEVICE_BROWSER(OfficialContextSlot.DEVICE, "deviceBrowser"),
    DEVICE_BROWSER_VERSION(OfficialContextSlot.DEVICE, "deviceBrowserVersion"),
    DEVICE_SCREEN_RESOLUTION(OfficialContextSlot.DEVICE, "deviceScreenResolution"),
    DEVICE_LANGUAGE(OfficialContextSlot.DEVICE, "deviceLanguage"),
    DEVICE_FINGERPRINT_MATCH(OfficialContextSlot.DEVICE, "deviceFingerprintMatch"),
    INTENT_BOT_USER_AGENT(OfficialContextSlot.INTENT, "intentBotUserAgent"),
    INTENT_MISSING_REFERER(OfficialContextSlot.INTENT, "intentMissingReferer"),
    INTENT_LANGUAGE_MISMATCH(OfficialContextSlot.INTENT, "intentLanguageMismatch"),
    INTENT_TLS_FINGERPRINT_ALTERED(OfficialContextSlot.INTENT, "intentTlsFingerprintAltered"),
    INTENT_ABNORMAL_HEADER_ORDER(OfficialContextSlot.INTENT, "intentAbnormalHeaderOrder"),
    IMPOSSIBLE_TRAVEL(OfficialContextSlot.INTENT, "impossibleTravel");

    private static final String CANONICAL_ATTRIBUTE_PREFIX = "ctxa.context.";

    private final OfficialContextSlot slot;
    private final String metadataKey;
    private final String canonicalAttributeKey;
    OfficialContextField(OfficialContextSlot slot, String metadataKey) {
        this.slot = slot;
        this.metadataKey = metadataKey;
        this.canonicalAttributeKey = CANONICAL_ATTRIBUTE_PREFIX + metadataKey;
    }

    public OfficialContextSlot slot() {
        return slot;
    }

    public String metadataKey() {
        return metadataKey;
    }

    public String canonicalAttributeKey() {
        return canonicalAttributeKey;
    }

    public Object extract(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        Object canonicalValue = request.getAttribute(canonicalAttributeKey);
        if (hasMaterialValue(canonicalValue)) {
            return canonicalValue;
        }
        Object neutralValue = request.getAttribute(metadataKey);
        if (hasMaterialValue(neutralValue)) {
            return neutralValue;
        }
        return null;
    }

    public void project(HttpServletRequest request, Object value, boolean overwriteExisting) {
        if (request == null || !hasMaterialValue(value)) {
            return;
        }
        projectAttribute(request, canonicalAttributeKey, value, overwriteExisting);
        projectAttribute(request, metadataKey, value, overwriteExisting);
    }

    private static void projectAttribute(
            HttpServletRequest request,
            String attributeName,
            Object value,
            boolean overwriteExisting
    ) {
        if (overwriteExisting || !hasMaterialValue(request.getAttribute(attributeName))) {
            request.setAttribute(attributeName, value);
        }
    }

    private static boolean hasMaterialValue(Object value) {
        if (value == null) {
            return false;
        }
        if (value instanceof String text) {
            return StringUtils.hasText(text);
        }
        return true;
    }

    public static OfficialContextField fromMetadataKey(String metadataKey) {
        if (!StringUtils.hasText(metadataKey)) {
            return null;
        }
        for (OfficialContextField field : values()) {
            if (field.metadataKey.equalsIgnoreCase(metadataKey.trim())) {
                return field;
            }
        }
        return null;
    }

    public boolean matchesMetadataKey(String metadataKey) {
        return StringUtils.hasText(metadataKey)
                && this.metadataKey.equalsIgnoreCase(metadataKey.trim().toLowerCase(Locale.ROOT));
    }
}
