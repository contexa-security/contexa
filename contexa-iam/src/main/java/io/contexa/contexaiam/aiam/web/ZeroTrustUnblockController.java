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
package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.aiam.web.dto.ZeroTrustDtos.ZeroTrustActionResponse;
import io.contexa.contexaiam.aiam.web.dto.ZeroTrustDtos.ZeroTrustInitiateSuccessResponse;
import io.contexa.contexaiam.aiam.web.dto.ZeroTrustDtos.ZeroTrustMessageResponse;
import io.contexa.contexaiam.aiam.web.dto.ZeroTrustDtos.ZeroTrustUnblockSuccessResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@Slf4j
@RestController
@RequestMapping("/admin/api/aiam/zero-trust")
@RequiredArgsConstructor
public class ZeroTrustUnblockController {

    private final BlockedUserService blockedUserService;
    private final BlockMfaStateStore blockMfaStateStore;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;

    @PostMapping("/initiate-block-mfa")
    public ResponseEntity<ZeroTrustActionResponse> initiateBlockMfa(Principal principal) {

        String userId = principal != null ? principal.getName() : null;
        if (userId == null) {
            return ResponseEntity.status(401)
                    .body(new ZeroTrustMessageResponse(false, "Authentication required"));
        }

        try {
            int failCount = blockMfaStateStore.getFailCount(userId);
            if (failCount >= securityZeroTrustProperties.getMaxBlockMfaAttempts()) {
                return ResponseEntity.status(403)
                        .body(new ZeroTrustMessageResponse(false, "MFA attempts exhausted"));
            }

            blockMfaStateStore.setPending(userId);

            return ResponseEntity.ok(new ZeroTrustInitiateSuccessResponse(true));

        } catch (Exception e) {
            log.error("[ZeroTrustUnblockController] Failed to initiate block MFA: userId={}", userId, e);
            return ResponseEntity.internalServerError()
                    .body(new ZeroTrustMessageResponse(false, "Failed to initiate MFA"));
        }
    }

    @PostMapping("/unblock-request")
    public ResponseEntity<ZeroTrustActionResponse> requestUnblock(
            Principal principal,
            @RequestBody(required = false) UnblockRequest request) {

        String userId = principal != null ? principal.getName() : null;
        if (userId == null) {
            return ResponseEntity.status(401)
                    .body(new ZeroTrustMessageResponse(false, "Authentication required"));
        }

        boolean mfaVerified = blockMfaStateStore.isVerified(userId);

        if (!mfaVerified) {
            return ResponseEntity.status(403)
                    .body(new ZeroTrustMessageResponse(
                            false,
                            "MFA verification required before unblock request"));
        }

        String reason = (request != null && request.getReason() != null && !request.getReason().isBlank())
                ? request.getReason()
                : null;

        if (reason == null) {
            return ResponseEntity.badRequest()
                    .body(new ZeroTrustMessageResponse(false, "Reason is required"));
        }

        try {
            blockedUserService.requestUnblockWithMfa(userId, reason, true);

            return ResponseEntity.ok(new ZeroTrustUnblockSuccessResponse(
                    true,
                    true,
                    "Unblock request submitted"));

        } catch (Exception e) {
            log.error("[ZeroTrustUnblockController] Failed to submit unblock request: userId={}", userId, e);
            return ResponseEntity.internalServerError()
                    .body(new ZeroTrustMessageResponse(false, "Failed to submit request"));
        }
    }

    public static class UnblockRequest {
        private String reason;

        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
    }
}
