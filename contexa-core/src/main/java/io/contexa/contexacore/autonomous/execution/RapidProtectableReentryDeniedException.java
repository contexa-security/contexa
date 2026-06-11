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
package io.contexa.contexacore.autonomous.execution;

import org.springframework.security.authorization.AuthorizationDeniedException;

public class RapidProtectableReentryDeniedException extends AuthorizationDeniedException {

    private static final long serialVersionUID = 1L;

    private final String resourceId;
    private final long windowSeconds;

    public RapidProtectableReentryDeniedException(String resourceId, long windowSeconds) {
        super(formatMessage(resourceId, windowSeconds));
        this.resourceId = resourceId;
        this.windowSeconds = windowSeconds;
    }

    public String getResourceId() {
        return resourceId;
    }

    public long getWindowSeconds() {
        return windowSeconds;
    }

    public int getHttpStatus() {
        return 429;
    }

    public String getErrorCode() {
        return "RAPID_PROTECTABLE_REENTRY";
    }

    private static String formatMessage(String resourceId, long windowSeconds) {
        return String.format(
                "Protected resource re-entry denied within %d seconds: %s",
                windowSeconds,
                resourceId != null ? resourceId : "unknown");
    }
}
