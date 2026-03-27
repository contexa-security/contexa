package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
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
    private final BlockedUserJpaRepository blockedUserJpaRepository;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String listBlockedUsers(
            @RequestParam(value = "filter", required = false, defaultValue = "all") String filter,
            @RequestParam(required = false) String keyword,
            Model model) {
        List<BlockedUser> blockedUsers;
        boolean hasKeyword = keyword != null && !keyword.isBlank();
        String likePattern = hasKeyword ? "%" + keyword.trim().toLowerCase() + "%" : null;

        if (hasKeyword) {
            blockedUsers = switch (filter) {
                case "blocked" -> blockedUserJpaRepository.searchByStatusAndUsername(BlockedUserStatus.BLOCKED, likePattern);
                case "unblock_requested" -> blockedUserJpaRepository.searchByStatusAndUsername(BlockedUserStatus.UNBLOCK_REQUESTED, likePattern);
                case "resolved" -> blockedUserJpaRepository.searchByStatusAndUsername(BlockedUserStatus.RESOLVED, likePattern);
                case "timeout_responded" -> blockedUserJpaRepository.searchByStatusAndUsername(BlockedUserStatus.TIMEOUT_RESPONDED, likePattern);
                case null, default -> blockedUserJpaRepository.searchByUsername(likePattern);
            };
        } else {
            blockedUsers = switch (filter) {
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
        }
        model.addAttribute("blockedUsers", blockedUsers);
        model.addAttribute("currentFilter", filter);
        model.addAttribute("keyword", keyword);
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
                    ra.addFlashAttribute("errorMessage", msg("msg.blacklist.not.found", id));
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
            ra.addFlashAttribute("message", msg("msg.blacklist.resolved"));
        } catch (Exception e) {
            log.error("[BlacklistController] Failed to resolve block: id={}", id, e);
            ra.addFlashAttribute("errorMessage", msg("msg.blacklist.resolve.error", e.getMessage()));
            return "redirect:/admin/blacklist/" + id;
        }
        return "redirect:/admin/blacklist";
    }

    @PostMapping("/{id}/delete")
    public String deleteBlockRecord(@PathVariable Long id, RedirectAttributes ra) {
        try {
            blockedUserService.deleteBlockRecord(id);
            ra.addFlashAttribute("message", msg("msg.blacklist.deleted"));
        } catch (Exception e) {
            log.error("[BlacklistController] Failed to delete block record: id={}", id, e);
            ra.addFlashAttribute("errorMessage", msg("msg.blacklist.delete.error", e.getMessage()));
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
