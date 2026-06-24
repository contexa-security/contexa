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
package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.hcad.projection.TrustedHcadContextProjection;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

public final class HcadActorSessionKeyFactory {

    private HcadActorSessionKeyFactory() {
    }

    public static String fromRequest(HttpServletRequest request, Authentication authentication) {
        AuthenticationStamp authenticationStamp = authenticationStamp(request);
        String userId = firstText(
                authenticationStamp != null ? authenticationStamp.principalId() : null,
                authentication != null ? authentication.getName() : null);
        String tenantId = stampAttribute(authenticationStamp, "tenantId");
        String organizationId = firstText(
                stampAttribute(authenticationStamp, "organizationId"),
                stampAttribute(authenticationStamp, "orgId"));
        String contextBindingHash = SessionFingerprintUtil.generateContextBindingHash(request);
        return fromParts(tenantId, organizationId, userId, contextBindingHash);
    }

    public static String fromProjection(TrustedHcadContextProjection projection) {
        if (projection == null) {
            return null;
        }
        return fromParts(
                projection.tenantId(),
                projection.organizationId(),
                projection.userId(),
                projection.contextBindingHash());
    }

    public static String fromParts(
            String tenantId,
            String organizationId,
            String userId,
            String contextBindingHash) {
        if (!StringUtils.hasText(userId) || !StringUtils.hasText(contextBindingHash)) {
            return null;
        }
        return PendingAnomalyKeyFactory.buildActorSessionKey(
                tenantId,
                organizationId,
                userId,
                contextBindingHash);
    }

    private static AuthenticationStamp authenticationStamp(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        Object rawStamp = request.getAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP);
        return rawStamp instanceof AuthenticationStamp stamp ? stamp : null;
    }

    private static String stampAttribute(AuthenticationStamp stamp, String key) {
        if (stamp == null || stamp.attributes() == null || !StringUtils.hasText(key)) {
            return null;
        }
        Object value = stamp.attributes().get(key);
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isBlank() ? null : text;
    }

    private static String firstText(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }
}
