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
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;

/**
 * Page controller serving Zero Trust BLOCK/ESCALATE dedicated pages.
 */
@Controller
@RequestMapping("/contexa/zero-trust")
@RequiredArgsConstructor
public class ZeroTrustPageController {

    private final BlockMfaStateStore blockMfaStateStore;
    private final BlockedUserService blockedUserService;
    private final SecurityZeroTrustProperties securityZeroTrustProperties;

    @GetMapping("/blocked")
    public String blocked(Principal principal, Model model) {

        boolean mfaVerified = false;
        boolean mfaFailed = false;
        int mfaFailCount = 0;
        if (principal != null) {
            String userId = principal.getName();

            mfaFailed = blockedUserService.hasLatestStatus(userId, BlockedUserStatus.MFA_FAILED);

            mfaVerified = blockMfaStateStore.isVerified(userId);
            mfaFailCount = blockMfaStateStore.getFailCount(userId);
        }
        int maxAttempts = securityZeroTrustProperties.getMaxBlockMfaAttempts();
        model.addAttribute("mfaVerified", mfaVerified);
        model.addAttribute("mfaFailed", mfaFailed);
        model.addAttribute("mfaFailCount", mfaFailCount);
        model.addAttribute("maxMfaAttempts", maxAttempts);
        model.addAttribute("mfaExhausted", mfaFailed || mfaFailCount >= maxAttempts);
        return "contexa/zero-trust/blocked";
    }

    @GetMapping("/challenge-required")
    public String challengeRequired(
            @RequestParam(value = "mfaUrl", required = false) String mfaUrl, Model model) {
        if (mfaUrl == null || mfaUrl.isBlank()) {
            mfaUrl = "/mfa/select-factor";
        }
        String safeMfaUrl = sanitizeRelativeUrl(mfaUrl, "/mfa/select-factor");
        model.addAttribute("mfaUrl", safeMfaUrl);
        return "contexa/zero-trust/challenge-required";
    }

    private String sanitizeRelativeUrl(String url, String fallback) {
        if (url == null || url.isBlank()) {
            return fallback;
        }
        if (url.contains("://") || url.startsWith("//")) {
            return fallback;
        }
        if (!url.startsWith("/")) {
            return fallback;
        }
        return url;
    }

    @GetMapping("/analysis-pending")
    public String analysisPending(
            @RequestParam(required = false, defaultValue = "/") String returnUrl,
            Model model) {
        model.addAttribute("returnUrl", returnUrl);
        return "contexa/zero-trust/analysis-pending";
    }
}
