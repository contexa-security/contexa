package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.admin.web.common.CsvColumn;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.domain.entity.ActiveSession;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Admin controller for session monitoring and forced invalidation.
 */
@Slf4j
@Controller
@RequestMapping("/admin/session-management")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('ADMIN')")
public class SessionManagementController {

    private static final int PAGE_SIZE = 20;
    private static final DateTimeFormatter TS_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final SessionManagementService sessionManagementService;
    private final MessageSource messageSource;
    private final CsvExportService csvExportService;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String list(@RequestParam(defaultValue = "0") int page, Model model) {
        model.addAttribute("activePage", "session-management");

        Page<ActiveSession> sessionPage = sessionManagementService.getActiveSessions(
                PageRequest.of(page, PAGE_SIZE, Sort.by(Sort.Direction.DESC, "lastAccessedAt")));

        long activeCount = sessionManagementService.getActiveSessionCount();

        model.addAttribute("sessionPage", sessionPage);
        model.addAttribute("activeCount", activeCount);
        return "admin/session-management";
    }

    @PostMapping("/{sessionId}/invalidate")
    public String invalidateSession(@PathVariable String sessionId, RedirectAttributes ra) {
        try {
            sessionManagementService.invalidateSession(sessionId);
            ra.addFlashAttribute("message", msg("admin.session.invalidated"));
        } catch (Exception e) {
            log.error("[SessionManagement] Failed to invalidate session: {}", sessionId, e);
            ra.addFlashAttribute("errorMessage", msg("msg.session.invalidate.error", e.getMessage()));
        }
        return "redirect:/admin/session-management";
    }

    @PostMapping("/user/{userId}/invalidate-all")
    public String invalidateAllForUser(@PathVariable String userId, RedirectAttributes ra) {
        try {
            sessionManagementService.invalidateAllSessionsForUser(userId);
            ra.addFlashAttribute("message", msg("admin.session.all.invalidated"));
        } catch (Exception e) {
            log.error("[SessionManagement] Failed to invalidate all sessions for user: {}", userId, e);
            ra.addFlashAttribute("errorMessage", msg("msg.session.invalidate.all.error", e.getMessage()));
        }
        return "redirect:/admin/session-management";
    }

    @GetMapping("/export")
    public void export(HttpServletResponse response) throws IOException {
        List<CsvColumn<ActiveSession>> columns = List.of(
                new CsvColumn<>("Session ID", s -> s.getSessionId() != null ? s.getSessionId() : ""),
                new CsvColumn<>("Username", s -> s.getUsername() != null ? s.getUsername() : ""),
                new CsvColumn<>("User ID", s -> s.getUserId() != null ? s.getUserId() : ""),
                new CsvColumn<>("IP Address", s -> s.getClientIp() != null ? s.getClientIp() : ""),
                new CsvColumn<>("User Agent", s -> s.getUserAgent() != null ? s.getUserAgent() : ""),
                new CsvColumn<>("Login Time", s -> s.getCreatedAt() != null ? s.getCreatedAt().format(TS_FORMAT) : ""),
                new CsvColumn<>("Last Active", s -> s.getLastAccessedAt() != null ? s.getLastAccessedAt().format(TS_FORMAT) : "")
        );

        csvExportService.export(response, "active-sessions", columns,
                () -> sessionManagementService.getAllActiveSessions().stream());
    }
}
