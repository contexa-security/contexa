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
package io.contexa.contexaiam.security.xacml.pep;

import io.contexa.contexacore.autonomous.execution.RapidProtectableReentryDeniedException;
import io.contexa.contexacore.autonomous.repository.ProtectableRapidReentryRepository;
import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacommon.security.context.OfficialContextRequestAttributes;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.core.Authentication;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Duration;
import java.util.Map;

@Slf4j
public class ProtectableRapidReentryGuard {

    private static final long DEFAULT_WINDOW_SECONDS = 5L;
    private static final Duration DEFAULT_WINDOW = Duration.ofSeconds(DEFAULT_WINDOW_SECONDS);

    private final ProtectableRapidReentryRepository repository;
    private final Duration window;

    public ProtectableRapidReentryGuard(ProtectableRapidReentryRepository repository) {
        this(repository, DEFAULT_WINDOW);
    }

    public ProtectableRapidReentryGuard(ProtectableRapidReentryRepository repository, Duration window) {
        this.repository = repository;
        this.window = window == null ? DEFAULT_WINDOW : window;
    }

    public void check(Authentication authentication, MethodInvocation methodInvocation) {
        if (!tryAcquire(authentication, methodInvocation)) {
            String scopeKey = buildRequestScopeKey(resolveCurrentRequest(), methodInvocation, "UNSPECIFIED");
            log.error("[ProtectableRapidReentryGuard] Rapid protected re-entry denied: userId={}, scope={}",
                    authentication != null ? authentication.getName() : null,
                    scopeKey);
            throw new RapidProtectableReentryDeniedException(scopeKey, Math.max(0L, window.toSeconds()));
        }
    }

    public boolean tryAcquire(Authentication authentication, MethodInvocation methodInvocation) {
        return tryAcquire(authentication, methodInvocation, "UNSPECIFIED");
    }

    public boolean tryAcquire(
            Authentication authentication,
            MethodInvocation methodInvocation,
            String decisionBoundaryMode) {
        if (window.isZero() || window.isNegative()) {
            return true;
        }

        if (authentication == null || !authentication.isAuthenticated()) {
            return true;
        }

        HttpServletRequest request = resolveCurrentRequest();
        if (request == null) {
            return true;
        }

        String userId = authentication.getName();
        if (userId == null || userId.isBlank()) {
            return true;
        }

        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);
        if (contextBindingHash == null || contextBindingHash.isBlank()) {
            return true;
        }

        String scopeKey = buildRequestScopeKey(request, methodInvocation, decisionBoundaryMode);
        return repository.tryAcquire(userId, contextBindingHash, scopeKey, window);
    }

    private HttpServletRequest resolveCurrentRequest() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            return attrs != null ? attrs.getRequest() : null;
        } catch (Exception e) {
            return null;
        }
    }
    private String buildRequestScopeKey(
            HttpServletRequest request,
            MethodInvocation methodInvocation,
            String decisionBoundaryMode) {
        Map<String, Object> officialContext = OfficialContextRequestAttributes.extractSnapshot(request);
        String tenantId = firstText(officialContext.get("tenantId"), officialContext.get("tenant_id"));
        String requestId = RequestInfoExtractor.extractRequestId(request);
        String httpMethod = normalize(request.getMethod(), "METHOD_UNSPECIFIED");
        String requestUri = normalize(request.getRequestURI(), "URI_UNSPECIFIED");
        String methodResource = methodInvocation == null || methodInvocation.getMethod() == null
                ? "RESOURCE_UNSPECIFIED"
                : methodInvocation.getMethod().getDeclaringClass().getName()
                        + "." + methodInvocation.getMethod().getName();
        return normalize(tenantId, "TENANT_UNSPECIFIED")
                + "|" + normalize(requestId, "REQUEST_UNSPECIFIED")
                + "|" + httpMethod
                + "|" + requestUri
                + "|" + methodResource
                + "|" + normalize(decisionBoundaryMode, "BOUNDARY_UNSPECIFIED");
    }

    private String firstText(Object... values) {
        if (values == null) {
            return null;
        }
        for (Object value : values) {
            if (value != null && !String.valueOf(value).isBlank()) {
                return String.valueOf(value).trim();
            }
        }
        return null;
    }

    private String normalize(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }
}
