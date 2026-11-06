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

import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.security.SameAppPath;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
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
    private boolean blockListOffered = true;

    /** Whether this screen leads a verified administrator to the block list; not behind the console's own chain. */
    public void setBlockListOffered(boolean blockListOffered) {
        this.blockListOffered = blockListOffered;
    }

    @GetMapping("/blocked")
    public String blocked(Principal principal, Model model, HttpServletRequest request) {

        boolean mfaVerified = false;
        boolean mfaFailed = false;
        boolean blockListOpen = false;
        int mfaFailCount = 0;
        if (principal != null) {
            String userId = ZeroTrustUserKey.person(principal.getName());

            mfaFailed = blockedUserService.hasLatestStatus(userId, BlockedUserStatus.MFA_FAILED);

            mfaVerified = blockMfaStateStore.isVerified(userId);
            mfaFailCount = blockMfaStateStore.getFailCount(userId);
            blockListOpen = blockListOffered && administrator(principal)
                    && blockMfaStateStore.isVerified(userId, SessionFingerprintUtil.verificationContext(request));
        }
        int maxAttempts = securityZeroTrustProperties.getMaxBlockMfaAttempts();
        model.addAttribute("mfaVerified", mfaVerified);
        model.addAttribute("mfaFailed", mfaFailed);
        model.addAttribute("blockListOpen", blockListOpen);
        model.addAttribute("mfaFailCount", mfaFailCount);
        model.addAttribute("maxMfaAttempts", maxAttempts);
        model.addAttribute("mfaExhausted", mfaFailed || mfaFailCount >= maxAttempts);
        return "contexa/zero-trust/blocked";
    }

    private static boolean administrator(Principal principal) {
        return principal instanceof Authentication authentication && ConsoleSession.administrator(authentication);
    }

    @GetMapping("/challenge-required")
    public String challengeRequired(
            @RequestParam(value = "mfaUrl", required = false) String mfaUrl,
            HttpServletRequest request, Model model) {
        String contextPath = request.getContextPath();
        model.addAttribute("mfaUrl", SameAppPath.orElse(mfaUrl, contextPath, contextPath + "/mfa/select-factor"));
        return "contexa/zero-trust/challenge-required";
    }

    @GetMapping("/analysis-pending")
    public String analysisPending(
            @RequestParam(required = false) String returnUrl,
            HttpServletRequest request, Model model) {
        String contextPath = request.getContextPath();
        model.addAttribute("returnUrl", SameAppPath.orElse(returnUrl, contextPath, contextPath + "/"));
        return "contexa/zero-trust/analysis-pending";
    }
}
