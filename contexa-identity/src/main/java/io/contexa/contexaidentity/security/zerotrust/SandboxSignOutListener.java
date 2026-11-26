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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.subject.ContexaBridge;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * bridge v2 B5-2 (section 6 of docs/agent/bridge-v2-연동표준-초안.md): in mode SANDBOX a sign-out of the application's own
 * Spring Security is told to Contexa as {@link ContexaBridge#signedOut} tells it, so an application that signs in with
 * Spring Security has nothing to call. Nothing of it may fail the application's logout: the call answers, never throws.
 */
public class SandboxSignOutListener implements ApplicationListener<LogoutSuccessEvent> {

    @Override
    public void onApplicationEvent(LogoutSuccessEvent event) {
        HttpServletRequest request = RequestContextHolder.getRequestAttributes() instanceof
                ServletRequestAttributes attributes ? attributes.getRequest() : null;
        String userId = ContexaIdentity.userId(request, event.getAuthentication());
        if (request != null && userId != null) {
            ContexaBridge.signedOut(request, userId);
        }
    }
}
