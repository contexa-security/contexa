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
package io.contexa.contexaidentity.security.filter.matcher;

public enum MfaRequestType {

    FACTOR_SELECTION("Factor selection processing"),

    CHALLENGE_INITIATION("Challenge initiation"),

    OTT_CODE_REQUEST("OTT code request"),

    OTT_CODE_VERIFY("OTT code verification"),

    FACTOR_VERIFICATION("Factor verification"),

    CANCEL_MFA("MFA cancellation"),

    LOGIN_PROCESSING("Login processing"),

    UNKNOWN("Unknown request");

    private final String description;

    MfaRequestType(String description) {
        this.description = description;
    }
    public String getDescription() {
        return description;
    }
}