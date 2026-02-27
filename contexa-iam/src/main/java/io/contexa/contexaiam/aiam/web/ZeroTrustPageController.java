package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
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

    private final StringRedisTemplate stringRedisTemplate;

    private static final int MAX_BLOCK_MFA_ATTEMPTS = 2;

    @GetMapping("/blocked")
    public String blocked(Principal principal, Model model) {

        boolean mfaVerified = false;
        int mfaFailCount = 0;
        if (principal != null) {
            String userId = principal.getName();
            String verifiedKey = ZeroTrustRedisKeys.blockMfaVerified(userId);
            mfaVerified = Boolean.parseBoolean(stringRedisTemplate.opsForValue().get(verifiedKey));

            String failCountKey = ZeroTrustRedisKeys.blockMfaFailCount(userId);
            String failCountStr = stringRedisTemplate.opsForValue().get(failCountKey);
            if (failCountStr != null) {
                try {
                    mfaFailCount = Integer.parseInt(failCountStr);
                } catch (NumberFormatException ignored) {
                }
            }
        }
        model.addAttribute("mfaVerified", mfaVerified);
        model.addAttribute("mfaFailCount", mfaFailCount);
        model.addAttribute("maxMfaAttempts", MAX_BLOCK_MFA_ATTEMPTS);
        model.addAttribute("mfaExhausted", mfaFailCount >= MAX_BLOCK_MFA_ATTEMPTS);
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
