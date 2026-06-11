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
package io.contexa.contexacommon.hcad.official;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Locale;

public enum OfficialContextField {
    TENANT_ID(
            OfficialContextSlot.SECURITY_SCOPE,
            "tenantId",
            List.of("tenantId", "ctxa.auth.tenantId", "hcad.tenant_id", "hcad.tenantId"),
            List.of("tenantId", "ctxa.auth.tenantId", "hcad.tenant_id")),
    ORGANIZATION_ID(
            OfficialContextSlot.SECURITY_SCOPE,
            "organizationId",
            List.of("organizationId", "ctxa.auth.organizationId", "hcad.organization_id", "hcad.organizationId"),
            List.of("organizationId", "ctxa.auth.organizationId", "hcad.organization_id")),
    ORG_ID(
            OfficialContextSlot.SECURITY_SCOPE,
            "orgId",
            List.of("orgId", "ctxa.auth.orgId", "hcad.org_id", "hcad.orgId"),
            List.of("orgId", "ctxa.auth.orgId", "hcad.org_id")),
    MFA_VERIFIED(
            OfficialContextSlot.SESSION,
            "mfaVerified",
            List.of("hcad.mfa_verified", "hcad.mfaVerified"),
            List.of("hcad.mfa_verified")),
    AUTHENTICATION_TYPE(
            OfficialContextSlot.SESSION,
            "authenticationType",
            List.of("hcad.authentication_type", "hcad.authenticationType", "hcad.auth_method", "hcad.authMethod"),
            List.of("hcad.authentication_type", "hcad.auth_method")),
    FAILED_LOGIN_ATTEMPTS(
            OfficialContextSlot.SESSION,
            "failedLoginAttempts",
            List.of("hcad.failed_login_attempts", "hcad.failedLoginAttempts"),
            List.of("hcad.failed_login_attempts")),
    RECENT_REQUEST_COUNT(
            OfficialContextSlot.SESSION,
            "recentRequestCount",
            List.of("hcad.recent_request_count", "hcad.recentRequestCount"),
            List.of("hcad.recent_request_count")),
    CURRENT_ACCESS_HOUR(
            OfficialContextSlot.SESSION,
            "currentAccessHour",
            List.of("hcad.current_access_hour", "hcad.currentAccessHour"),
            List.of("hcad.current_access_hour")),
    CONCURRENT_SESSIONS(
            OfficialContextSlot.SESSION,
            "concurrentSessions",
            List.of("hcad.concurrent_sessions", "hcad.concurrentSessions"),
            List.of("hcad.concurrent_sessions")),
    PASSWORD_AGE_DAYS(
            OfficialContextSlot.SESSION,
            "passwordAgeDays",
            List.of("hcad.password_age_days", "hcad.passwordAgeDays"),
            List.of("hcad.password_age_days")),
    SESSION_AGE_MINUTES(
            OfficialContextSlot.SESSION,
            "sessionAgeMinutes",
            List.of("hcad.session_age_minutes", "hcad.sessionAgeMinutes"),
            List.of("hcad.session_age_minutes")),
    COUNTRY(
            OfficialContextSlot.LOCATION,
            "country",
            List.of("hcad.country"),
            List.of("hcad.country")),
    CITY(
            OfficialContextSlot.LOCATION,
            "city",
            List.of("hcad.city"),
            List.of("hcad.city")),
    IP_BAND(
            OfficialContextSlot.LOCATION,
            "ipBand",
            List.of("hcad.ip_band", "hcad.ipBand"),
            List.of("hcad.ip_band")),
    ASN(
            OfficialContextSlot.LOCATION,
            "asn",
            List.of("hcad.asn", "hcad.geoAsn"),
            List.of("hcad.asn")),
    DEVICE_OS(
            OfficialContextSlot.DEVICE,
            "deviceOs",
            List.of("hcad.device_os", "hcad.deviceOs"),
            List.of("hcad.device_os")),
    DEVICE_OS_VERSION(
            OfficialContextSlot.DEVICE,
            "deviceOsVersion",
            List.of("hcad.device_os_version", "hcad.deviceOsVersion"),
            List.of("hcad.device_os_version")),
    DEVICE_BROWSER(
            OfficialContextSlot.DEVICE,
            "deviceBrowser",
            List.of("hcad.device_browser", "hcad.deviceBrowser"),
            List.of("hcad.device_browser")),
    DEVICE_BROWSER_VERSION(
            OfficialContextSlot.DEVICE,
            "deviceBrowserVersion",
            List.of("hcad.device_browser_version", "hcad.deviceBrowserVersion"),
            List.of("hcad.device_browser_version")),
    DEVICE_SCREEN_RESOLUTION(
            OfficialContextSlot.DEVICE,
            "deviceScreenResolution",
            List.of("hcad.device_screen_resolution", "hcad.deviceScreenResolution"),
            List.of("hcad.device_screen_resolution")),
    DEVICE_LANGUAGE(
            OfficialContextSlot.DEVICE,
            "deviceLanguage",
            List.of("hcad.device_language", "hcad.deviceLanguage"),
            List.of("hcad.device_language")),
    DEVICE_FINGERPRINT_MATCH(
            OfficialContextSlot.DEVICE,
            "deviceFingerprintMatch",
            List.of("hcad.device_fingerprint_match", "hcad.deviceFingerprintMatch"),
            List.of("hcad.device_fingerprint_match")),
    INTENT_BOT_USER_AGENT(
            OfficialContextSlot.INTENT,
            "intentBotUserAgent",
            List.of("hcad.intent_bot_user_agent", "hcad.intentBotUserAgent"),
            List.of("hcad.intent_bot_user_agent")),
    INTENT_MISSING_REFERER(
            OfficialContextSlot.INTENT,
            "intentMissingReferer",
            List.of("hcad.intent_missing_referer", "hcad.intentMissingReferer"),
            List.of("hcad.intent_missing_referer")),
    INTENT_LANGUAGE_MISMATCH(
            OfficialContextSlot.INTENT,
            "intentLanguageMismatch",
            List.of("hcad.intent_language_mismatch", "hcad.intentLanguageMismatch"),
            List.of("hcad.intent_language_mismatch")),
    INTENT_TLS_FINGERPRINT_ALTERED(
            OfficialContextSlot.INTENT,
            "intentTlsFingerprintAltered",
            List.of("hcad.intent_tls_fingerprint_altered", "hcad.intentTlsFingerprintAltered"),
            List.of("hcad.intent_tls_fingerprint_altered")),
    INTENT_ABNORMAL_HEADER_ORDER(
            OfficialContextSlot.INTENT,
            "intentAbnormalHeaderOrder",
            List.of("hcad.intent_abnormal_header_order", "hcad.intentAbnormalHeaderOrder"),
            List.of("hcad.intent_abnormal_header_order")),
    IMPOSSIBLE_TRAVEL(
            OfficialContextSlot.INTENT,
            "impossibleTravel",
            List.of("hcad.impossibleTravel"),
            List.of("hcad.impossibleTravel"));

    private final OfficialContextSlot slot;
    private final String metadataKey;
    private final List<String> attributeCandidates;
    private final List<String> projectionTargets;

    OfficialContextField(
            OfficialContextSlot slot,
            String metadataKey,
            List<String> attributeCandidates,
            List<String> projectionTargets
    ) {
        this.slot = slot;
        this.metadataKey = metadataKey;
        this.attributeCandidates = List.copyOf(attributeCandidates);
        this.projectionTargets = List.copyOf(projectionTargets);
    }

    public OfficialContextSlot slot() {
        return slot;
    }

    public String metadataKey() {
        return metadataKey;
    }

    public Object extract(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        for (String candidate : attributeCandidates) {
            Object value = request.getAttribute(candidate);
            if (hasMaterialValue(value)) {
                return value;
            }
        }
        return null;
    }

    public void project(HttpServletRequest request, Object value, boolean overwriteExisting) {
        if (request == null || !hasMaterialValue(value)) {
            return;
        }
        for (String target : projectionTargets) {
            if (overwriteExisting || !hasMaterialValue(request.getAttribute(target))) {
                request.setAttribute(target, value);
            }
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
