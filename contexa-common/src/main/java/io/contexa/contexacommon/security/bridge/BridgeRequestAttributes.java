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
package io.contexa.contexacommon.security.bridge;

public final class BridgeRequestAttributes {

    public static final String RESOLUTION_RESULT = "ctxa.bridge.resolution";
    public static final String AUTHENTICATION_STAMP = "ctxa.bridge.authentication.stamp";
    public static final String AUTHORIZATION_STAMP = "ctxa.bridge.authorization.stamp";
    public static final String DELEGATION_STAMP = "ctxa.bridge.delegation.stamp";
    public static final String COVERAGE_REPORT = "ctxa.bridge.coverage.report";
    public static final String USER_SYNC_RESULT = "ctxa.bridge.user.sync.result";

    private BridgeRequestAttributes() {
    }
}
