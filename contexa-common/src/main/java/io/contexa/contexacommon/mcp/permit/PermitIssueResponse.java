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
package io.contexa.contexacommon.mcp.permit;

public record PermitIssueResponse(
        boolean issued,
        String permitId,
        String status,
        String reason) {

    public static PermitIssueResponse issued(String permitId, String status) {
        return new PermitIssueResponse(true, permitId, status, null);
    }

    public static PermitIssueResponse rejected(String reason) {
        return new PermitIssueResponse(false, null, null, reason);
    }
}