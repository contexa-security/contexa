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
package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.dto.BlacklistApiDtos.BlacklistActionResponse;
import io.contexa.contexaiam.admin.web.auth.dto.BlacklistApiDtos.BlockedUserResponse;
import io.contexa.contexaiam.admin.web.auth.dto.BlacklistApiDtos.ResolveBlockRequest;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/admin/api/blacklist")
@RequiredArgsConstructor
public class BlacklistApiController {

    private final BlockedUserService blockedUserService;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<BlockedUserResponse>> listBlockedUsers(
            @RequestParam(value = "status", required = false) String status) {
        if ("BLOCKED".equalsIgnoreCase(status)) {
            return ResponseEntity.ok(blockedUserService.getBlockedUsers().stream()
                    .map(BlockedUserResponse::from)
                    .toList());
        }
        return ResponseEntity.ok(blockedUserService.getAllBlockHistory().stream()
                .map(BlockedUserResponse::from)
                .toList());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<BlockedUserResponse> getBlockDetail(@PathVariable Long id) {
        return blockedUserService.getBlockDetail(id)
                .map(BlockedUserResponse::from)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/{id}/resolve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<BlacklistActionResponse> resolveBlock(
            @PathVariable Long id,
            @RequestBody(required = false) ResolveBlockRequest request) {
        if (request == null) {
            return ResponseEntity.badRequest()
                    .body(BlacklistActionResponse.failed("request body is required"));
        }
        if (request.getResolvedAction() == null || request.getResolvedAction().isBlank()) {
            return ResponseEntity.badRequest()
                    .body(BlacklistActionResponse.failed("resolvedAction is required"));
        }
        if (request.getReason() == null || request.getReason().isBlank()) {
            return ResponseEntity.badRequest()
                    .body(BlacklistActionResponse.failed("reason is required"));
        }

        try {
            String adminId = extractCurrentUserId();
            blockedUserService.resolveBlockById(id, adminId, request.getResolvedAction(),
                    request.getReason());
            return ResponseEntity.ok(BlacklistActionResponse.resolved(id, request.getResolvedAction()));
        } catch (Exception e) {
            log.error("[BlacklistApi] Failed to resolve block: id={}", id, e);
            return ResponseEntity.internalServerError()
                    .body(BlacklistActionResponse.failed(e.getMessage()));
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<BlacklistActionResponse> deleteBlockRecord(@PathVariable Long id) {
        try {
            blockedUserService.deleteBlockRecord(id);
            return ResponseEntity.ok(BlacklistActionResponse.deleted(id));
        } catch (Exception e) {
            log.error("[BlacklistApi] Failed to delete block record: id={}", id, e);
            return ResponseEntity.internalServerError()
                    .body(BlacklistActionResponse.failed(e.getMessage()));
        }
    }

    private String extractCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName() != null) {
            return auth.getName();
        }
        throw new IllegalStateException(msg("msg.auth.user.not.found"));
    }
}
