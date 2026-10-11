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
package io.contexa.contexacore.autonomous.store;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Stores a failed sign-in once per request. The same failure reaches the store from the authentication failure event,
 * the failure handler and the login policy; the first of them stores it and marks the request, so the user's count says
 * how many times the user failed, not how many paths saw the failure. Outside a request every call stores.
 */
public final class LoginFailureRecording {

    private static final String RECORDED_USER_ATTRIBUTE = LoginFailureRecording.class.getName() + ".user";

    private LoginFailureRecording() {
    }

    public static void recordOnce(SecurityContextDataStore store, String userId, String clientIp, long failedAtMs) {
        if (store == null) {
            return;
        }
        HttpServletRequest request = currentRequest();
        if (request != null && StringUtils.hasText(userId)) {
            String user = userId.trim();
            if (user.equals(request.getAttribute(RECORDED_USER_ATTRIBUTE))) {
                return;
            }
            request.setAttribute(RECORDED_USER_ATTRIBUTE, user);
        }
        store.recordLoginFailure(userId, clientIp, failedAtMs);
    }

    private static HttpServletRequest currentRequest() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
                ? attributes.getRequest()
                : null;
    }
}
