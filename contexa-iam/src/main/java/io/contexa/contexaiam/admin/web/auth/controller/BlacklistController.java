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

import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.List;

@Slf4j
@Controller
@RequestMapping("/contexa/admin/blacklist")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class BlacklistController {

    private final BlockedUserService blockedUserService;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String listBlockedUsers(
            @RequestParam(value = "filter", required = false, defaultValue = "all") String filter,
            @RequestParam(required = false) String keyword,
            Model model) {
        List<BlockedUser> blockedUsers = blockedUserService.findBlockedUsers(filter, keyword);
        model.addAttribute("blockedUsers", blockedUsers);
        model.addAttribute("currentFilter", filter);
        model.addAttribute("keyword", keyword);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        model.addAttribute("ownBlockAwaitsVerification",
                auth != null && blockedUserService.ownBlockAwaitsVerification(auth.getName()));
        return "contexa/admin/blacklist";
    }

    @GetMapping("/{id}")
    public String getBlockDetail(@PathVariable Long id, Model model, RedirectAttributes ra) {
        return blockedUserService.getBlockDetail(id)
                .map(blocked -> {
                    model.addAttribute("blocked", blocked);
                    return "contexa/admin/blacklist-detail";
                })
                .orElseGet(() -> {
                    ra.addFlashAttribute("errorMessage", msg("msg.blacklist.not.found", id));
                    return "redirect:/contexa/admin/blacklist";
                });
    }

    /** Q-1: the way out for a user who has no factor to answer a CHALLENGE with. */
    @PostMapping("/challenge-release")
    public String releaseChallenge(@RequestParam("userId") String userId, @RequestParam("reason") String reason,
                                   RedirectAttributes ra) {
        try {
            boolean released = blockedUserService.releaseChallenge(userId, extractCurrentUserId(), reason);
            if (released) {
                ra.addFlashAttribute("message", msg("msg.blacklist.challenge.released", userId));
            } else {
                ra.addFlashAttribute("errorMessage", msg("msg.blacklist.challenge.none", userId));
            }
        } catch (AccessDeniedException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", msg("msg.blacklist.challenge.input"));
        }
        return "redirect:/contexa/admin/blacklist";
    }

    @PostMapping("/{id}/resolve")
    public String resolveBlock(@PathVariable Long id,
                               @RequestParam("resolvedAction") String resolvedAction,
                               @RequestParam("reason") String reason,
                               RedirectAttributes ra) {
        try {
            String adminId = extractCurrentUserId();
            blockedUserService.resolveBlockById(id, adminId, resolvedAction, reason);
            ra.addFlashAttribute("message", msg("msg.blacklist.resolved"));
        } catch (AccessDeniedException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
            return "redirect:/contexa/admin/blacklist/" + id;
        } catch (Exception e) {
            log.error("[BlacklistController] Failed to resolve block: id={}", id, e);
            ra.addFlashAttribute("errorMessage", msg("msg.blacklist.resolve.error", e.getMessage()));
            return "redirect:/contexa/admin/blacklist/" + id;
        }
        return "redirect:/contexa/admin/blacklist";
    }

    @PostMapping("/{id}/delete")
    public String deleteBlockRecord(@PathVariable Long id, RedirectAttributes ra) {
        try {
            blockedUserService.deleteBlockRecord(id, extractCurrentUserId());
            ra.addFlashAttribute("message", msg("msg.blacklist.deleted"));
        } catch (AccessDeniedException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
        } catch (Exception e) {
            log.error("[BlacklistController] Failed to delete block record: id={}", id, e);
            ra.addFlashAttribute("errorMessage", msg("msg.blacklist.delete.error", e.getMessage()));
        }
        return "redirect:/contexa/admin/blacklist";
    }

    private String extractCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName() != null) {
            return auth.getName();
        }
        throw new IllegalStateException(msg("msg.auth.user.not.found"));
    }
}
