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
package io.contexa.contexacore.security.session;

import jakarta.servlet.http.HttpServletRequest;

public interface SessionIdResolver {

    String resolve(HttpServletRequest request);

    boolean isValid(String sessionId);

    SessionSource getSource(HttpServletRequest request);

    enum SessionSource {
        COOKIE("Extracted from Cookie"),
        HEADER("Extracted from HTTP Header"),
        ATTRIBUTE("Extracted from Request Attribute"),
        BEARER("Extracted from Bearer Token"),
        NONE("No Session ID");

        private final String description;

        SessionSource(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }
}