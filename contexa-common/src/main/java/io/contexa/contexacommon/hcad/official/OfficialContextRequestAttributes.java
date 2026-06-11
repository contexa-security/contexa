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

import io.contexa.contexacommon.hcad.domain.HCADContext;
import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;
import java.util.Map;

public final class OfficialContextRequestAttributes {

    private OfficialContextRequestAttributes() {
    }

    public static Map<String, Object> extractSnapshot(HttpServletRequest request) {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        if (request == null) {
            return snapshot;
        }
        for (OfficialContextField field : OfficialContextField.values()) {
            Object value = field.extract(request);
            if (value != null) {
                snapshot.put(field.metadataKey(), value);
            }
        }
        return snapshot;
    }

    public static void applySnapshot(HttpServletRequest request, Map<String, ?> snapshot, boolean overwriteExisting) {
        if (request == null || snapshot == null || snapshot.isEmpty()) {
            return;
        }
        for (Map.Entry<String, ?> entry : snapshot.entrySet()) {
            OfficialContextField field = OfficialContextField.fromMetadataKey(entry.getKey());
            if (field != null) {
                field.project(request, entry.getValue(), overwriteExisting);
            }
        }
    }

    public static Map<String, Object> snapshotFrom(HCADContext context) {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        if (context == null) {
            return snapshot;
        }

        put(snapshot, OfficialContextField.MFA_VERIFIED, context.getHasValidMFA());
        put(snapshot, OfficialContextField.AUTHENTICATION_TYPE,
                context.getAuthenticationType() != null ? context.getAuthenticationType() : context.getAuthenticationMethod());
        put(snapshot, OfficialContextField.FAILED_LOGIN_ATTEMPTS, context.getFailedLoginAttempts());
        put(snapshot, OfficialContextField.RECENT_REQUEST_COUNT, context.getRecentRequestCount());
        put(snapshot, OfficialContextField.CURRENT_ACCESS_HOUR, context.getCurrentAccessHour());
        put(snapshot, OfficialContextField.CONCURRENT_SESSIONS, context.getConcurrentSessions());
        put(snapshot, OfficialContextField.PASSWORD_AGE_DAYS, context.getPasswordAgeDays());
        put(snapshot, OfficialContextField.SESSION_AGE_MINUTES, context.getSessionAgeMinutes());
        put(snapshot, OfficialContextField.COUNTRY, context.getCountry());
        put(snapshot, OfficialContextField.CITY, context.getCity());
        put(snapshot, OfficialContextField.IP_BAND, context.getIpBand());
        put(snapshot, OfficialContextField.ASN, context.getAsn());
        put(snapshot, OfficialContextField.DEVICE_OS, context.getDeviceOs());
        put(snapshot, OfficialContextField.DEVICE_OS_VERSION, context.getDeviceOsVersion());
        put(snapshot, OfficialContextField.DEVICE_BROWSER, context.getDeviceBrowser());
        put(snapshot, OfficialContextField.DEVICE_BROWSER_VERSION, context.getDeviceBrowserVersion());
        put(snapshot, OfficialContextField.DEVICE_SCREEN_RESOLUTION, context.getDeviceScreenResolution());
        put(snapshot, OfficialContextField.DEVICE_LANGUAGE, context.getDeviceLanguage());
        put(snapshot, OfficialContextField.DEVICE_FINGERPRINT_MATCH, context.getDeviceFingerprintMatch());
        put(snapshot, OfficialContextField.INTENT_BOT_USER_AGENT, context.getIntentBotUserAgent());
        put(snapshot, OfficialContextField.INTENT_MISSING_REFERER, context.getIntentMissingReferer());
        put(snapshot, OfficialContextField.INTENT_LANGUAGE_MISMATCH, context.getIntentLanguageMismatch());
        put(snapshot, OfficialContextField.INTENT_TLS_FINGERPRINT_ALTERED, context.getIntentTlsFingerprintAltered());
        put(snapshot, OfficialContextField.INTENT_ABNORMAL_HEADER_ORDER, context.getIntentAbnormalHeaderOrder());

        Map<String, Object> additionalAttributes = context.getAdditionalAttributes();
        if (additionalAttributes != null) {
            put(snapshot, OfficialContextField.TENANT_ID, additionalAttributes.get("tenantId"));
            put(snapshot, OfficialContextField.ORGANIZATION_ID, additionalAttributes.get("organizationId"));
            put(snapshot, OfficialContextField.ORG_ID, additionalAttributes.get("orgId"));
        }
        if (additionalAttributes != null && additionalAttributes.get("impossibleTravel") != null) {
            put(snapshot, OfficialContextField.IMPOSSIBLE_TRAVEL, additionalAttributes.get("impossibleTravel"));
        }
        return snapshot;
    }

    private static void put(Map<String, Object> snapshot, OfficialContextField field, Object value) {
        if (field != null && value != null) {
            snapshot.put(field.metadataKey(), value);
        }
    }
}
