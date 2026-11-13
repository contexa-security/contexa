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

import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacommon.security.ContexaConsolePaths;
import io.contexa.contexaiam.admin.web.auth.service.PasswordChangeService;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequiredArgsConstructor
public class PasswordChangeController {

    private static final AuthenticationTrustResolver TRUST_RESOLVER = new AuthenticationTrustResolverImpl();

    private final PasswordChangeService passwordChangeService;
    private final PasswordPolicyService passwordPolicyService;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    /**
     * A signed-in person changes the password of the own account, whatever the address names: the change of another
     * account is refused to a signed-in person (PasswordChangeService), so its form is not shown either. Without a sign-in,
     * a sign-in refused for an expired password names the account in the session, not in the address.
     */
    @GetMapping(ContexaConsolePaths.PASSWORD_CHANGE)
    public String showPasswordChangeForm(@RequestParam(required = false) String username, HttpSession session,
                                         Model model) {
        String account = signedInName();
        if (account == null) {
            account = StringUtils.hasText(username) ? username
                    : (String) session.getAttribute(ContexaConsolePaths.PASSWORD_CHANGE_USERNAME_ATTRIBUTE);
        }
        if (!StringUtils.hasText(account)) {
            return "redirect:/contexa/admin/login";
        }
        model.addAttribute("username", account);
        model.addAttribute("policy", passwordPolicyService.getCurrentPolicy());
        return "contexa/password-change";
    }

    @PostMapping(ContexaConsolePaths.PASSWORD_CHANGE)
    public String processPasswordChange(
            @RequestParam String username,
            @RequestParam String currentPassword,
            @RequestParam String newPassword,
            @RequestParam String confirmPassword,
            HttpServletRequest request,
            RedirectAttributes ra) {
        try {
            passwordChangeService.changePassword(username, currentPassword, newPassword, confirmPassword,
                    SessionFingerprintUtil.extractClientIp(request));
        } catch (PasswordChangeService.PasswordChangeException e) {
            ra.addFlashAttribute("errorMessage", msg(e.getMessageKey(), e.getMessageArgs()));
            request.getSession(true).setAttribute(ContexaConsolePaths.PASSWORD_CHANGE_USERNAME_ATTRIBUTE, username);
            return "redirect:" + ContexaConsolePaths.PASSWORD_CHANGE;
        }

        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(ContexaConsolePaths.PASSWORD_CHANGE_USERNAME_ATTRIBUTE);
        }
        // The sign-in this leads to is reached through further redirects, which spend a flash attribute on the way: the
        // flag in the address goes along to it (LoginController), and the sign-in page says the password was changed.
        return "redirect:/contexa/admin/login?" + LoginController.PASSWORD_CHANGED_PARAMETER;
    }

    @Nullable
    private static String signedInName() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.isAuthenticated()
                && !TRUST_RESOLVER.isAnonymous(authentication) && StringUtils.hasText(authentication.getName())
                ? authentication.getName() : null;
    }
}