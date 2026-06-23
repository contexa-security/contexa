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
package io.contexa.contexacore.hcad.projection;

import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionResult;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.hcad.promotion.HcadPreProtectablePromotionSignal;
import io.contexa.contexacore.hcad.store.BaselineDataStore;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import io.contexa.contexacore.hcad.trigger.HcadRequestPathUtils;
import io.contexa.contexacore.hcad.trigger.PendingAnomalyKeyFactory;
import io.contexa.contexacore.properties.HcadProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class TrustedHcadContextProjectionFactory {

    private static final long REQUEST_BURST_WINDOW_MS = Duration.ofMinutes(5).toMillis();
    private static final List<String> UNTRUSTED_HEADER_PREFIXES = List.of("x-contexa-");
    private static final String LIGHTWEIGHT_REQUEST_RECORDED_ATTRIBUTE = "hcad.lightweightRequestRecorded";

    private final HCADDataStore hcadDataStore;
    private final SecurityContextDataStore securityContextDataStore;
    private final BaselineDataStore baselineDataStore;
    private final HcadProperties hcadProperties;

    public TrustedHcadContextProjectionFactory(
            HCADDataStore hcadDataStore,
            SecurityContextDataStore securityContextDataStore,
            HcadProperties hcadProperties) {
        this(hcadDataStore, securityContextDataStore, null, hcadProperties);
    }

    public TrustedHcadContextProjectionFactory(
            HCADDataStore hcadDataStore,
            SecurityContextDataStore securityContextDataStore,
            BaselineDataStore baselineDataStore,
            HcadProperties hcadProperties) {
        this.hcadDataStore = hcadDataStore;
        this.securityContextDataStore = securityContextDataStore;
        this.baselineDataStore = baselineDataStore;
        this.hcadProperties = hcadProperties;
    }

    public TrustedHcadContextProjection project(HttpServletRequest request, Authentication authentication) {
        Map<String, HcadFieldProvenance> provenance = new LinkedHashMap<>();
        Map<String, Object> ignoredInputs = collectIgnoredInputs(request, provenance);
        AuthenticationStamp authenticationStamp = resolveAuthenticationStamp(request);
        AuthorizationStamp authorizationStamp = resolveAuthorizationStamp(request);
        long now = System.currentTimeMillis();

        String userId = firstText(
                authenticationStamp != null ? authenticationStamp.principalId() : null,
                authentication != null ? authentication.getName() : null);
        putProvenance(provenance, "userId", userId,
                authenticationStamp != null && StringUtils.hasText(authenticationStamp.principalId())
                        ? HcadTrustedSource.BRIDGE_VERIFIED
                        : HcadTrustedSource.TRUSTED_SERVER,
                "Resolved from bridge authentication stamp or Spring Security authentication.");

        String tenantId = textAttribute(authenticationStamp, "tenantId");
        putProvenance(provenance, "tenantId", tenantId, HcadTrustedSource.BRIDGE_VERIFIED,
                "Resolved from bridge authentication stamp attributes.");

        String organizationId = firstText(textAttribute(authenticationStamp, "organizationId"), textAttribute(authenticationStamp, "orgId"));
        putProvenance(provenance, "organizationId", organizationId, HcadTrustedSource.BRIDGE_VERIFIED,
                "Resolved from bridge authentication stamp attributes.");

        String sessionId = resolveServerSessionId(request, authenticationStamp);
        putProvenance(provenance, "sessionId", sessionId,
                hasServerSession(request) ? HcadTrustedSource.TRUSTED_SERVER : HcadTrustedSource.BRIDGE_VERIFIED,
                "Resolved from existing server session or bridge authentication stamp.");

        String method = request != null ? request.getMethod() : null;
        putProvenance(provenance, "method", method, HcadTrustedSource.TRUSTED_SERVER,
                "Resolved from HttpServletRequest method.");

        String normalizedPath = request != null ? HcadRequestPathUtils.normalizedPath(request) : null;
        putProvenance(provenance, "normalizedPath", normalizedPath, HcadTrustedSource.TRUSTED_SERVER,
                "Resolved from server request URI normalization.");

        String clientIp = request != null ? request.getRemoteAddr() : null;
        putProvenance(provenance, "clientIp", clientIp, HcadTrustedSource.TRUSTED_SERVER,
                "Resolved from servlet container remote address only.");

        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(
                sessionId,
                clientIp,
                request != null ? request.getHeader("User-Agent") : null);
        putProvenance(provenance, "contextBindingHash", contextBindingHash, HcadTrustedSource.TRUSTED_SERVER,
                "Generated from trusted session, remote address, and user agent.");

        String authenticationMethodRaw = firstText(
                authenticationStamp != null ? authenticationStamp.authenticationType() : null,
                authentication != null ? authentication.getClass().getSimpleName() : null);
        String authenticationMethod = firstText(
                SecuritySemanticNormalizer.normalizeAuthenticationType(authenticationMethodRaw),
                authenticationMethodRaw);
        putProvenance(provenance, "authenticationMethod", authenticationMethod,
                authenticationStamp != null && StringUtils.hasText(authenticationStamp.authenticationType())
                        ? HcadTrustedSource.BRIDGE_VERIFIED
                        : HcadTrustedSource.TRUSTED_SERVER,
                "Resolved from bridge authentication stamp or Spring Security authentication type.");

        String authenticationAssurance = authenticationStamp != null ? authenticationStamp.authenticationAssurance() : null;
        putProvenance(provenance, "authenticationAssurance", authenticationAssurance, HcadTrustedSource.BRIDGE_VERIFIED,
                "Resolved from bridge authentication stamp assurance.");

        Boolean mfaVerified = authenticationStamp != null && authenticationStamp.mfaCompleted() != null
                ? authenticationStamp.mfaCompleted()
                : hasMfaAuthority(authentication);
        putProvenance(provenance, "mfaVerified", mfaVerified,
                authenticationStamp != null && authenticationStamp.mfaCompleted() != null
                        ? HcadTrustedSource.BRIDGE_VERIFIED
                        : HcadTrustedSource.TRUSTED_SERVER,
                "Resolved from bridge MFA stamp or server authentication authorities.");

        Long mfaFreshnessSeconds = authenticationStamp != null && authenticationStamp.authenticationTime() != null
                ? Duration.between(authenticationStamp.authenticationTime(), Instant.now()).toSeconds()
                : null;
        putProvenance(provenance, "mfaFreshnessSeconds", mfaFreshnessSeconds, HcadTrustedSource.BRIDGE_VERIFIED,
                "Resolved from bridge authentication time.");

        String authorizationPolicyId = authorizationStamp != null ? authorizationStamp.policyId() : null;
        putProvenance(provenance, "authorizationPolicyId", authorizationPolicyId, HcadTrustedSource.BRIDGE_VERIFIED,
                "Resolved from bridge authorization stamp policy.");

        Boolean authorizationPrivileged = authorizationStamp != null ? authorizationStamp.privileged() : null;
        putProvenance(provenance, "authorizationPrivileged", authorizationPrivileged, HcadTrustedSource.BRIDGE_VERIFIED,
                "Resolved from bridge authorization stamp privilege flag.");

        Boolean verificationRequired = booleanAttribute(authorizationStamp, "verificationRequired");
        putProvenance(provenance, "verificationRequired", verificationRequired, HcadTrustedSource.BRIDGE_VERIFIED,
                "Resolved from bridge authorization stamp attributes.");

        List<String> recentPermissionChanges = recentPermissionChanges(tenantId, userId);
        putProvenance(provenance, "recentPermissionChanges", recentPermissionChanges.isEmpty() ? null : recentPermissionChanges,
                HcadTrustedSource.STORE_DERIVED,
                "Resolved from server-side security context store.");

        int failedLoginBurst = failedLoginBurst(sessionId, userId, clientIp, now);
        putProvenance(provenance, "failedLoginBurst", failedLoginBurst, HcadTrustedSource.STORE_DERIVED,
                "Resolved from server-side session action history and login failure counters.");

        int requestBurst = requestBurst(userId, now);
        putProvenance(provenance, "requestBurst", requestBurst, HcadTrustedSource.STORE_DERIVED,
                "Resolved from HCAD request counter store.");

        String previousPath = previousPath(sessionId, userId);
        putProvenance(provenance, "previousPath", previousPath, HcadTrustedSource.STORE_DERIVED,
                "Resolved from server-side previous path store.");

        Boolean rapidSequence = rapidSequence(sessionId, userId, now);
        putProvenance(provenance, "rapidSequence", rapidSequence, HcadTrustedSource.STORE_DERIVED,
                "Resolved from server-side last request timestamp.");

        Map<Object, Object> sessionMetadata = sessionMetadata(sessionId);
        Boolean impossibleTravel = asBoolean(sessionMetadata.get("impossibleTravel"));
        putProvenance(provenance, "impossibleTravel", impossibleTravel, HcadTrustedSource.STORE_DERIVED,
                "Resolved from server-side session metadata.");

        Double baselineConfidence = asDouble(sessionMetadata.get("baselineConfidence"));
        putProvenance(provenance, "baselineConfidence", baselineConfidence, HcadTrustedSource.STORE_DERIVED,
                "Resolved from server-side session metadata.");
        Boolean baselineEstablished = baselineConfidence != null;
        putProvenance(provenance, "baselineEstablished", baselineEstablished, HcadTrustedSource.STORE_DERIVED,
                "Derived from baseline confidence availability.");

        HcadBaselineComparison baselineComparison = comparePersonalBaseline(
                userId,
                normalizedPath,
                method,
                clientIp,
                request != null ? request.getHeader("User-Agent") : null,
                authenticationMethod,
                now);
        putProvenance(provenance, "baselineComparison",
                baselineComparison.available() ? baselineComparison : null,
                HcadTrustedSource.STORE_DERIVED,
                "Compared current trusted request context with the persisted user baseline.");

        updateStoresAfterProjection(request, sessionId, userId, normalizedPath, now);

        return new TrustedHcadContextProjection(
                userId,
                tenantId,
                organizationId,
                sessionId,
                contextBindingHash,
                method,
                normalizedPath,
                clientIp,
                authenticationMethod,
                authenticationAssurance,
                mfaVerified,
                mfaFreshnessSeconds,
                authorizationPolicyId,
                authorizationPrivileged,
                verificationRequired,
                recentPermissionChanges,
                failedLoginBurst,
                requestBurst,
                rapidSequence,
                previousPath,
                impossibleTravel,
                baselineConfidence,
                baselineEstablished,
                baselineComparison,
                HcadPromptSecurityContextFieldRegistry.version(),
                HcadPromptSecurityContextFieldRegistry.snapshot(provenance),
                provenance,
                ignoredInputs);
    }

    public void recordLightweightRequestCounter(HttpServletRequest request, Authentication authentication) {
        if (request == null || HcadRequestPathUtils.isNonUserInteractionRequest(request)) {
            return;
        }
        AuthenticationStamp authenticationStamp = resolveAuthenticationStamp(request);
        String userId = firstText(
                authenticationStamp != null ? authenticationStamp.principalId() : null,
                authentication != null ? authentication.getName() : null);
        if (hcadDataStore != null && StringUtils.hasText(userId)) {
            hcadDataStore.recordRequest(userId, System.currentTimeMillis());
            request.setAttribute(LIGHTWEIGHT_REQUEST_RECORDED_ATTRIBUTE, true);
        }
    }

    public void recordLightweightSessionNarrative(HttpServletRequest request, Authentication authentication) {
        if (request == null || HcadRequestPathUtils.isNonUserInteractionRequest(request)) {
            return;
        }
        AuthenticationStamp authenticationStamp = resolveAuthenticationStamp(request);
        String userId = firstText(
                authenticationStamp != null ? authenticationStamp.principalId() : null,
                authentication != null ? authentication.getName() : null);
        String sessionId = resolveServerSessionId(request, authenticationStamp);
        String normalizedPath = HcadRequestPathUtils.normalizedPath(request);
        updateSessionNarrativeStores(sessionId, userId, normalizedPath, System.currentTimeMillis());
    }

    public HcadTrustedAnchorSignalProbe probeAnchorSignals(HttpServletRequest request, Authentication authentication) {
        AuthenticationStamp authenticationStamp = resolveAuthenticationStamp(request);
        AuthorizationStamp authorizationStamp = resolveAuthorizationStamp(request);
        String userId = firstText(
                authenticationStamp != null ? authenticationStamp.principalId() : null,
                authentication != null ? authentication.getName() : null);
        String tenantId = textAttribute(authenticationStamp, "tenantId");
        String organizationId = firstText(textAttribute(authenticationStamp, "organizationId"), textAttribute(authenticationStamp, "orgId"));
        String sessionId = resolveServerSessionId(request, authenticationStamp);
        String authenticationMethodRaw = firstText(
                authenticationStamp != null ? authenticationStamp.authenticationType() : null,
                authentication != null ? authentication.getClass().getSimpleName() : null);
        String authenticationMethod = firstText(
                SecuritySemanticNormalizer.normalizeAuthenticationType(authenticationMethodRaw),
                authenticationMethodRaw);
        Boolean mfaVerified = authenticationStamp != null && authenticationStamp.mfaCompleted() != null
                ? authenticationStamp.mfaCompleted()
                : hasMfaAuthority(authentication);
        Long mfaFreshnessSeconds = authenticationStamp != null && authenticationStamp.authenticationTime() != null
                ? Duration.between(authenticationStamp.authenticationTime(), Instant.now()).toSeconds()
                : null;
        Boolean authorizationPrivileged = authorizationStamp != null ? authorizationStamp.privileged() : null;
        Boolean verificationRequired = booleanAttribute(authorizationStamp, "verificationRequired");

        List<String> anchors = new ArrayList<>();
        Map<Object, Object> metadata = sessionMetadata(sessionId);
        if (Boolean.TRUE.equals(asBoolean(metadata.get("impossibleTravel")))) {
            anchors.add(HcadPreProtectablePromotionSignal.IMPOSSIBLE_TRAVEL.name());
        }
        String clientIp = request != null ? request.getRemoteAddr() : null;
        if (failedLoginBurst(sessionId, userId, clientIp, System.currentTimeMillis())
                >= hcadProperties.getPreTrigger().getFailedLoginBurstThreshold()) {
            anchors.add(HcadPreProtectablePromotionSignal.FAILED_LOGIN_BURST.name());
        }
        if (isAuthContextInconsistent(authenticationMethod, mfaVerified)) {
            anchors.add(HcadPreProtectablePromotionSignal.AUTH_CONTEXT_INCONSISTENT.name());
        }
        if (!recentPermissionChanges(tenantId, userId).isEmpty()) {
            anchors.add(HcadPreProtectablePromotionSignal.RECENT_PERMISSION_CHANGE.name());
        }
        if (Boolean.TRUE.equals(authorizationPrivileged)) {
            anchors.add(HcadPreProtectablePromotionSignal.PRIVILEGED_AUTHORIZATION.name());
        }
        if (isFreshMfaRequiredButNotFresh(verificationRequired, mfaVerified, mfaFreshnessSeconds)) {
            anchors.add(HcadPreProtectablePromotionSignal.FRESH_MFA_REQUIRED.name());
        }
        return new HcadTrustedAnchorSignalProbe(
                anchors,
                PendingAnomalyKeyFactory.buildTrustedAnchorSignature(anchors));
    }

    private HcadBaselineComparison comparePersonalBaseline(
            String userId,
            String normalizedPath,
            String method,
            String clientIp,
            String userAgent,
            String authenticationMethod,
            long now) {
        int minSamples = hcadProperties.getBaseline().getStatistical().getMinSamples();
        if (!StringUtils.hasText(userId) || baselineDataStore == null) {
            return HcadBaselineComparison.unavailable(minSamples);
        }
        BaselineVector baseline = baselineDataStore.getUserBaseline(userId);
        if (baseline == null) {
            return HcadBaselineComparison.unavailable(minSamples);
        }

        long updateCount = baseline.getUpdateCount() == null ? 0L : baseline.getUpdateCount();
        boolean established = updateCount >= minSamples;
        ZonedDateTime observedAt = Instant.ofEpochMilli(now).atZone(ZoneId.systemDefault());

        String currentIpBand = SecuritySemanticNormalizer.normalizeNetwork(clientIp, null);
        String currentPathFamily = SecuritySemanticNormalizer.normalizePathFamily(normalizedPath);
        String currentAuthType = SecuritySemanticNormalizer.normalizeAuthenticationType(authenticationMethod);
        String currentUserAgentSignature = SecurityEventEnricher.extractBrowserSignature(userAgent);
        String currentOs = SecurityEventEnricher.extractOSFromUserAgent(userAgent);
        String currentBrowser = extractBrowserName(currentUserAgentSignature);

        Map<String, Object> currentValues = new LinkedHashMap<>();
        currentValues.put("ipBand", currentIpBand);
        currentValues.put("accessHour", observedAt.getHour());
        currentValues.put("accessDay", observedAt.getDayOfWeek().getValue());
        currentValues.put("pathFamily", currentPathFamily);
        currentValues.put("httpMethod", method);
        currentValues.put("userAgent", currentUserAgentSignature);
        currentValues.put("operatingSystem", currentOs);
        currentValues.put("browser", currentBrowser);
        currentValues.put("authenticationType", currentAuthType);

        Map<String, Object> baselineValues = new LinkedHashMap<>();
        baselineValues.put("updateCount", updateCount);
        List<String> baselineIpBands = normalizeNetworks(baseline.getNormalIpRanges(), baseline.getNormalIpBands());
        baselineValues.put("normalIpBands", baselineIpBands);
        baselineValues.put("normalAccessHours", integers(baseline.getNormalAccessHours()));
        baselineValues.put("normalAccessDays", integers(baseline.getNormalAccessDays()));
        baselineValues.put("frequentPaths", strings(baseline.getFrequentPaths()));
        baselineValues.put("frequentResourceFamilies", strings(baseline.getFrequentResourceFamilies()));
        baselineValues.put("normalUserAgents", strings(baseline.getNormalUserAgents()));
        baselineValues.put("normalOperatingSystems", strings(baseline.getNormalOperatingSystems()));
        baselineValues.put("normalBrowsers", strings(baseline.getNormalBrowsers()));
        baselineValues.put("normalAuthenticationTypes", strings(baseline.getNormalAuthenticationTypes()));

        List<String> matched = new ArrayList<>();
        List<String> mismatched = new ArrayList<>();
        List<String> missing = new ArrayList<>();
        if (!established) {
            missing.add("personalBaselineInsufficientSamples");
            return new HcadBaselineComparison(
                    true,
                    false,
                    updateCount,
                    minSamples,
                    0,
                    0,
                    0.0d,
                    false,
                    matched,
                    mismatched,
                    missing,
                    currentValues,
                    baselineValues);
        }

        compareStringDimension("ipBand", currentIpBand, baselineIpBands, matched, mismatched, missing, false);
        compareIntegerDimension("accessHour", observedAt.getHour(), baseline.getNormalAccessHours(), matched, mismatched, missing);
        compareIntegerDimension("accessDay", observedAt.getDayOfWeek().getValue(), baseline.getNormalAccessDays(), matched, mismatched, missing);
        comparePathDimension("pathFamily", currentPathFamily, baseline.getFrequentPaths(), baseline.getFrequentResourceFamilies(), matched, mismatched, missing);
        compareStringDimension("userAgent", currentUserAgentSignature, baseline.getNormalUserAgents(), matched, mismatched, missing, false);
        compareStringDimension("operatingSystem", currentOs, baseline.getNormalOperatingSystems(), matched, mismatched, missing, false);
        compareStringDimension("browser", currentBrowser, baseline.getNormalBrowsers(), matched, mismatched, missing, false);
        compareStringDimension("authenticationType", currentAuthType, baseline.getNormalAuthenticationTypes(), matched, mismatched, missing, false);

        int compared = matched.size() + mismatched.size();
        double matchRatio = compared == 0 ? 0.0d : (double) matched.size() / compared;
        boolean materialMismatch = compared >= 3 && mismatched.size() >= 2 && matchRatio < 0.70d;

        return new HcadBaselineComparison(
                true,
                true,
                updateCount,
                minSamples,
                compared,
                mismatched.size(),
                matchRatio,
                materialMismatch,
                matched,
                mismatched,
                missing,
                currentValues,
                baselineValues);
    }

    private void compareStringDimension(
            String dimension,
            String currentValue,
            String[] baselineValues,
            List<String> matched,
            List<String> mismatched,
            List<String> missing,
            boolean pathFamily) {
        List<String> normalizedBaselineValues = normalizeStrings(baselineValues, pathFamily);
        compareStringDimension(dimension, currentValue, normalizedBaselineValues, matched, mismatched, missing, pathFamily);
    }

    private void compareStringDimension(
            String dimension,
            String currentValue,
            List<String> normalizedBaselineValues,
            List<String> matched,
            List<String> mismatched,
            List<String> missing,
            boolean pathFamily) {
        if (!StringUtils.hasText(currentValue) || normalizedBaselineValues.isEmpty()) {
            missing.add(dimension);
            return;
        }
        String normalizedCurrent = pathFamily
                ? normalizePathValue(currentValue)
                : normalizeComparable(currentValue);
        if (normalizedBaselineValues.contains(normalizedCurrent)) {
            matched.add(dimension);
        } else {
            mismatched.add(dimension);
        }
    }

    private void comparePathDimension(
            String dimension,
            String currentPathFamily,
            String[] frequentPaths,
            String[] frequentResourceFamilies,
            List<String> matched,
            List<String> mismatched,
            List<String> missing) {
        List<String> baselineValues = new ArrayList<>();
        baselineValues.addAll(normalizeStrings(frequentPaths, true));
        baselineValues.addAll(normalizeStrings(frequentResourceFamilies, true));
        if (!StringUtils.hasText(currentPathFamily) || baselineValues.isEmpty()) {
            missing.add(dimension);
            return;
        }
        if (baselineValues.contains(normalizePathValue(currentPathFamily))) {
            matched.add(dimension);
        } else {
            mismatched.add(dimension);
        }
    }

    private void compareIntegerDimension(
            String dimension,
            Integer currentValue,
            Integer[] baselineValues,
            List<String> matched,
            List<String> mismatched,
            List<String> missing) {
        List<Integer> values = baselineValues == null
                ? List.of()
                : Arrays.stream(baselineValues).filter(value -> value != null).distinct().toList();
        if (currentValue == null || values.isEmpty()) {
            missing.add(dimension);
            return;
        }
        if (values.contains(currentValue)) {
            matched.add(dimension);
        } else {
            mismatched.add(dimension);
        }
    }

    private AuthenticationStamp resolveAuthenticationStamp(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        Object rawStamp = request.getAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP);
        if (rawStamp instanceof AuthenticationStamp stamp) {
            return stamp;
        }
        Object rawResolution = request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        if (rawResolution instanceof BridgeResolutionResult result) {
            return result.authenticationStamp();
        }
        return null;
    }

    private AuthorizationStamp resolveAuthorizationStamp(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        Object rawStamp = request.getAttribute(BridgeRequestAttributes.AUTHORIZATION_STAMP);
        if (rawStamp instanceof AuthorizationStamp stamp) {
            return stamp;
        }
        Object rawResolution = request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        if (rawResolution instanceof BridgeResolutionResult result) {
            return result.authorizationStamp();
        }
        return null;
    }

    private Map<String, Object> collectIgnoredInputs(HttpServletRequest request, Map<String, HcadFieldProvenance> provenance) {
        if (request == null) {
            return Map.of();
        }
        Map<String, Object> ignoredInputs = new LinkedHashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames != null && headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String normalized = headerName == null ? "" : headerName.toLowerCase(Locale.ROOT);
            boolean ignored = UNTRUSTED_HEADER_PREFIXES.stream().anyMatch(normalized::startsWith);
            if (!ignored) {
                continue;
            }
            ignoredInputs.put("header." + headerName, request.getHeader(headerName));
            provenance.put("header." + headerName, HcadFieldProvenance.ignored(
                    "header." + headerName,
                    "Client-supplied Contexa header is excluded from HCAD pre-trigger scoring."));
        }
        return ignoredInputs;
    }

    private String resolveServerSessionId(HttpServletRequest request, AuthenticationStamp authenticationStamp) {
        if (request != null) {
            HttpSession session = request.getSession(false);
            if (session != null && StringUtils.hasText(session.getId())) {
                return session.getId();
            }
        }
        return authenticationStamp != null ? authenticationStamp.sessionId() : null;
    }

    private boolean hasServerSession(HttpServletRequest request) {
        return request != null && request.getSession(false) != null;
    }

    private List<String> recentPermissionChanges(String tenantId, String userId) {
        if (!StringUtils.hasText(tenantId) || !StringUtils.hasText(userId) || securityContextDataStore == null) {
            return List.of();
        }
        List<String> changes = securityContextDataStore.getRecentPermissionChangeObservations(
                tenantId,
                userId,
                hcadProperties.getPreTrigger().getPermissionChangeObservationLimit());
        return changes == null ? List.of() : List.copyOf(changes);
    }

    private int failedLoginBurst(String sessionId, String userId, String clientIp, long now) {
        int sessionActionCount = sessionLoginFailureActionCount(sessionId);
        int persistedCounterCount = hcadDataStore == null
                ? 0
                : hcadDataStore.getRecentLoginFailureCount(userId, clientIp, now - REQUEST_BURST_WINDOW_MS, now);
        return Math.max(sessionActionCount, persistedCounterCount);
    }

    private int sessionLoginFailureActionCount(String sessionId) {
        if (!StringUtils.hasText(sessionId) || securityContextDataStore == null) {
            return 0;
        }
        List<String> actions = securityContextDataStore.getRecentSessionActions(sessionId, 20);
        if (actions == null || actions.isEmpty()) {
            return 0;
        }
        int count = 0;
        for (String action : actions) {
            String normalized = action == null ? "" : action.toUpperCase(Locale.ROOT);
            if (normalized.contains("AUTHENTICATION_FAILURE") || normalized.contains("LOGIN_FAILURE")) {
                count++;
            }
        }
        return count;
    }

    private int requestBurst(String userId, long now) {
        if (!StringUtils.hasText(userId) || hcadDataStore == null) {
            return 0;
        }
        return hcadDataStore.getRecentRequestCount(userId, now - REQUEST_BURST_WINDOW_MS, now);
    }

    private String previousPath(String sessionId, String userId) {
        if (securityContextDataStore == null) {
            return null;
        }
        if (StringUtils.hasText(sessionId)) {
            String previous = securityContextDataStore.getSessionPreviousPath(sessionId);
            if (StringUtils.hasText(previous)) {
                return previous;
            }
        }
        if (!StringUtils.hasText(userId)) {
            return null;
        }
        String previous = securityContextDataStore.getPreviousPath(userId);
        return StringUtils.hasText(previous) ? previous : null;
    }

    private Boolean rapidSequence(String sessionId, String userId, long now) {
        Long lastRequestTime = null;
        if (securityContextDataStore != null && StringUtils.hasText(sessionId)) {
            lastRequestTime = securityContextDataStore.getSessionLastRequestTime(sessionId);
        }
        if (lastRequestTime == null && securityContextDataStore != null && StringUtils.hasText(userId)) {
            lastRequestTime = securityContextDataStore.getLastRequestTime(userId);
        }
        if (lastRequestTime == null) {
            return false;
        }
        long elapsed = Math.max(0L, now - lastRequestTime);
        return elapsed <= hcadProperties.getPreTrigger().getRapidRequestIntervalMs();
    }

    private Map<Object, Object> sessionMetadata(String sessionId) {
        if (!StringUtils.hasText(sessionId) || hcadDataStore == null) {
            return Map.of();
        }
        Map<Object, Object> metadata = hcadDataStore.getSessionMetadata(sessionId);
        return metadata == null ? Map.of() : metadata;
    }

    private void updateStoresAfterProjection(
            HttpServletRequest request,
            String sessionId,
            String userId,
            String normalizedPath,
            long now) {
        if (HcadRequestPathUtils.isNonUserInteractionRequest(request)) {
            return;
        }
        boolean requestCounterAlreadyRecorded = request != null
                && Boolean.TRUE.equals(request.getAttribute(LIGHTWEIGHT_REQUEST_RECORDED_ATTRIBUTE));
        if (!requestCounterAlreadyRecorded && hcadDataStore != null && StringUtils.hasText(userId)) {
            hcadDataStore.recordRequest(userId, now);
        }
        updateSessionNarrativeStores(sessionId, userId, normalizedPath, now);
    }

    private void updateSessionNarrativeStores(
            String sessionId,
            String userId,
            String normalizedPath,
            long now) {
        if (securityContextDataStore == null) {
            return;
        }
        if (StringUtils.hasText(sessionId)) {
            Long last = securityContextDataStore.getSessionLastRequestTime(sessionId);
            if (last != null) {
                securityContextDataStore.addSessionRequestInterval(sessionId, Math.max(0L, now - last));
            }
            securityContextDataStore.setSessionLastRequestTime(sessionId, now);
            if (StringUtils.hasText(normalizedPath)) {
                securityContextDataStore.setSessionPreviousPath(sessionId, normalizedPath);
            }
        }
        if (StringUtils.hasText(userId)) {
            securityContextDataStore.setLastRequestTime(userId, now);
            if (StringUtils.hasText(normalizedPath)) {
                securityContextDataStore.setPreviousPath(userId, normalizedPath);
            }
            if (StringUtils.hasText(sessionId)) {
                securityContextDataStore.trackUserSession(userId, sessionId);
            }
        }
    }

    private void putProvenance(
            Map<String, HcadFieldProvenance> provenance,
            String field,
            Object value,
            HcadTrustedSource source,
            String reason) {
        if (value == null) {
            provenance.put(field, HcadFieldProvenance.absent(field, reason));
            return;
        }
        if (value instanceof String text && !StringUtils.hasText(text)) {
            provenance.put(field, HcadFieldProvenance.absent(field, reason));
            return;
        }
        provenance.put(field, HcadFieldProvenance.present(field, source, reason));
    }

    private boolean hasMfaAuthority(Authentication authentication) {
        if (authentication == null || authentication.getAuthorities() == null) {
            return false;
        }
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if (authority != null && authority.getAuthority() != null
                    && authority.getAuthority().toUpperCase(Locale.ROOT).contains("MFA")) {
                return true;
            }
        }
        return false;
    }

    private String textAttribute(AuthenticationStamp stamp, String key) {
        if (stamp == null || stamp.attributes() == null) {
            return null;
        }
        Object value = stamp.attributes().get(key);
        return value == null ? null : value.toString();
    }

    private Boolean booleanAttribute(AuthorizationStamp stamp, String key) {
        if (stamp == null || stamp.attributes() == null) {
            return null;
        }
        return asBoolean(stamp.attributes().get(key));
    }

    private Boolean asBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            String normalized = text.trim().toLowerCase(Locale.ROOT);
            if ("true".equals(normalized) || "1".equals(normalized) || "yes".equals(normalized)) {
                return true;
            }
            if ("false".equals(normalized) || "0".equals(normalized) || "no".equals(normalized)) {
                return false;
            }
        }
        return null;
    }

    private Double asDouble(Object value) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            try {
                return Double.parseDouble(text.trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private List<String> strings(String[] values) {
        if (values == null || values.length == 0) {
            return List.of();
        }
        return Arrays.stream(values)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private List<String> normalizeNetworks(String[]... valueGroups) {
        if (valueGroups == null || valueGroups.length == 0) {
            return List.of();
        }
        return Arrays.stream(valueGroups)
                .filter(values -> values != null && values.length > 0)
                .flatMap(Arrays::stream)
                .filter(StringUtils::hasText)
                .map(value -> SecuritySemanticNormalizer.normalizeNetwork(value, value))
                .map(this::normalizeComparable)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private List<Integer> integers(Integer[] values) {
        if (values == null || values.length == 0) {
            return List.of();
        }
        return Arrays.stream(values)
                .filter(value -> value != null)
                .distinct()
                .toList();
    }

    private List<String> normalizeStrings(String[] values, boolean pathFamily) {
        if (values == null || values.length == 0) {
            return List.of();
        }
        return Arrays.stream(values)
                .filter(StringUtils::hasText)
                .map(value -> pathFamily ? normalizePathValue(value) : normalizeComparable(value))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private String normalizePathValue(String value) {
        String pathFamily = SecuritySemanticNormalizer.normalizePathFamily(value);
        return normalizeComparable(pathFamily != null ? pathFamily : value);
    }

    private String normalizeComparable(String value) {
        return value == null ? null : value.trim().toLowerCase(Locale.ROOT);
    }

    private String extractBrowserName(String userAgentSignature) {
        if (!StringUtils.hasText(userAgentSignature)) {
            return "Unknown";
        }
        int slash = userAgentSignature.indexOf('/');
        return slash > 0 ? userAgentSignature.substring(0, slash) : userAgentSignature;
    }

    private boolean isAuthContextInconsistent(String authenticationMethod, Boolean mfaVerified) {
        String authMethod = normalizeComparable(authenticationMethod);
        return ("mfa".equals(authMethod) || "mfa_only".equals(authMethod)) && !Boolean.TRUE.equals(mfaVerified);
    }

    private boolean isFreshMfaRequiredButNotFresh(
            Boolean verificationRequired,
            Boolean mfaVerified,
            Long mfaFreshnessSeconds) {
        if (!Boolean.TRUE.equals(verificationRequired)) {
            return false;
        }
        if (!Boolean.TRUE.equals(mfaVerified)) {
            return true;
        }
        return mfaFreshnessSeconds != null
                && mfaFreshnessSeconds > hcadProperties.getPreTrigger().getFreshMfaMaxAgeSeconds();
    }

    private String firstText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value;
            }
        }
        return null;
    }
}
