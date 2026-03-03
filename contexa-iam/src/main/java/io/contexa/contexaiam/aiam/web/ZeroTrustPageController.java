package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
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
@RequestMapping("/zero-trust")
@RequiredArgsConstructor
public class ZeroTrustPageController {

    private final BlockMfaStateStore blockMfaStateStore;
    private final BlockedUserJpaRepository blockedUserJpaRepository;

    private static final int MAX_BLOCK_MFA_ATTEMPTS = 2;

    @GetMapping("/blocked")
    public String blocked(Principal principal, Model model) {

        boolean mfaVerified = false;
        boolean mfaFailed = false;
        int mfaFailCount = 0;
        if (principal != null) {
            String userId = principal.getName();

            mfaFailed = blockedUserJpaRepository
                    .findFirstByUserIdOrderByBlockedAtDesc(userId)
                    .map(bu -> bu.getStatus() == BlockedUserStatus.MFA_FAILED)
                    .orElse(false);

            mfaVerified = blockMfaStateStore.isVerified(userId);
            mfaFailCount = blockMfaStateStore.getFailCount(userId);
        }
        model.addAttribute("mfaVerified", mfaVerified);
        model.addAttribute("mfaFailed", mfaFailed);
        model.addAttribute("mfaFailCount", mfaFailCount);
        model.addAttribute("maxMfaAttempts", MAX_BLOCK_MFA_ATTEMPTS);
        model.addAttribute("mfaExhausted", mfaFailed || mfaFailCount >= MAX_BLOCK_MFA_ATTEMPTS);
        return "zero-trust/blocked";
    }

    @GetMapping("/challenge-required")
    public String challengeRequired(
            @RequestParam(value = "mfaUrl", required = false,
                    defaultValue = "/mfa/select-factor") String mfaUrl, Model model) {
        String safeMfaUrl = sanitizeRelativeUrl(mfaUrl, "/mfa/select-factor");
        model.addAttribute("mfaUrl", safeMfaUrl);
        return "zero-trust/challenge-required";
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
        return "zero-trust/analysis-pending";
    }
}
