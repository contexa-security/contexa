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
package io.contexa.autoconfigure.iam.admin;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * The console header's sign-out when the application owns sign-in (HOST_OWNED): {@code /logout} is the application's,
 * so the header posts to the console chain's own sign-out, which keeps the application's session.
 */
@ControllerAdvice(basePackages = "io.contexa")
public final class HostOwnedConsoleModelAdvice {

    @ModelAttribute("adminLogoutUrl")
    public String adminLogoutUrl() {
        return HostOwnedAdminConsoleAutoConfiguration.LOGOUT_URL;
    }
}
