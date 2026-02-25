package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Slf4j
@Controller
@RequestMapping("/admin/blacklist")
@RequiredArgsConstructor
public class BlacklistController {

    private final BlockedUserService blockedUserService;

    @GetMapping
    public String listBlockedUsers(
            @RequestParam(value = "filter", required = false, defaultValue = "all") String filter,
            Model model) {
        List<BlockedUser> blockedUsers = switch (filter) {
            case "blocked" -> blockedUserService.getBlockedUsers();
            case "unblock_requested" -> blockedUserService.getUnblockRequested();
            case "resolved" -> blockedUserService.getAllBlockHistory().stream()
                    .filter(b -> b.getStatus() == BlockedUserStatus.RESOLVED)
                    .toList();
            case "timeout_responded" -> blockedUserService.getAllBlockHistory().stream()
                    .filter(b -> b.getStatus() == BlockedUserStatus.TIMEOUT_RESPONDED)
                    .toList();
            case null, default -> blockedUserService.getAllBlockHistory();
        };
        model.addAttribute("blockedUsers", blockedUsers);
        model.addAttribute("currentFilter", filter);
        return "admin/blacklist";
    }

    @GetMapping("/{id}")
    public String getBlockDetail(@PathVariable Long id, Model model, RedirectAttributes ra) {
        return blockedUserService.getBlockDetail(id)
                .map(blocked -> {
                    model.addAttribute("blocked", blocked);
                    return "admin/blacklist-detail";
                })
                .orElseGet(() -> {
                    ra.addFlashAttribute("errorMessage", "Block record not found: id=" + id);
                    return "redirect:/admin/blacklist";
                });
    }

    @PostMapping("/{id}/resolve")
    public String resolveBlock(@PathVariable Long id,
                               @RequestParam("resolvedAction") String resolvedAction,
                               @RequestParam("reason") String reason,
                               RedirectAttributes ra) {
        try {
            String adminId = extractCurrentUserId();
            blockedUserService.resolveBlockById(id, adminId, resolvedAction, reason);
            ra.addFlashAttribute("message", "Block resolved successfully.");
        } catch (Exception e) {
            log.error("[BlacklistController] Failed to resolve block: id={}", id, e);
            ra.addFlashAttribute("errorMessage", "Failed to resolve block: " + e.getMessage());
            return "redirect:/admin/blacklist/" + id;
        }
        return "redirect:/admin/blacklist";
    }

    @PostMapping("/{id}/delete")
    public String deleteBlockRecord(@PathVariable Long id, RedirectAttributes ra) {
        try {
            blockedUserService.deleteBlockRecord(id);
            ra.addFlashAttribute("message", "Block record deleted successfully.");
        } catch (Exception e) {
            log.error("[BlacklistController] Failed to delete block record: id={}", id, e);
            ra.addFlashAttribute("errorMessage", "Failed to delete: " + e.getMessage());
        }
        return "redirect:/admin/blacklist";
    }

    private String extractCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName() != null) {
            return auth.getName();
        }
        throw new IllegalStateException("Authenticated user not found");
    }
}
