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
package io.contexa.contexaiam.admin.promptquality.status;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.report.PromptQualityReportController;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityScreens;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionService;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleMessages;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;

import java.util.Locale;
import java.util.Objects;

/**
 * Quality plan 3.6, 3.8: the state of quality, the screen that answers how right the prompt in use is and what there is
 * to check, and the data it draws ({@link PromptQualityStatus}): the latest measurement of the version in use, its
 * operation metrics beside those of the version it replaced, and what there is to check, each with the way to the
 * screen that settles it. The quality report is exported from its head (PromptQualityReportController). An
 * administrator's screen, as every screen of the group.
 */
@Controller
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PromptQualityStatusController {

    static final String API = "/contexa/admin/api/prompt-quality/status";
    /** The menu entry of the screen (data-menu.sql). */
    static final String ACTIVE_PAGE = "prompt-quality-status";
    /** The review queue of the decision records, where "review" leads. */
    static final String REVIEW_QUEUE = "/contexa/admin/zero-trust/decisions?view=review";
    /** The decision records. */
    static final String DECISIONS = "/contexa/admin/zero-trust/decisions";
    /**
     * The messages the screen reads: its own, the report button's, the period buttons', the console's status words,
     * units and the words of a screen that could not be read.
     */
    static final String[] MESSAGE_PREFIXES = {"pqa.status.", "pqa.report.ui.", "zt.console.ui.period.",
            "zt.console.ui.status.", "zt.console.ui.unit.", "zt.console.ui.loadFailed"};

    private final PromptQualityStatus status;
    private final MessageSource messages;
    private final ObjectMapper objectMapper;

    /**
     * @param objectMapper Contexa's own JSON writer (the configuration passes it by its name), for the messages and
     *                     the addresses of the screen
     */
    public PromptQualityStatusController(PromptQualityStatus status, MessageSource messages,
                                         @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        this.status = Objects.requireNonNull(status, "status");
        this.messages = messages;
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @GetMapping({PromptQualityScreens.STATUS, PromptQualityScreens.STATUS + "/"})
    public String page(Model model, Locale locale, Authentication authentication) {
        requireAdmin(authentication);
        model.addAttribute("screen", "status");
        model.addAttribute("activePage", ACTIVE_PAGE);
        model.addAttribute("apiBase", API);
        model.addAttribute("scriptMessagesJson", ZeroTrustConsoleMessages.json(messages, locale, objectMapper,
                MESSAGE_PREFIXES));
        model.addAttribute("pathsJson", json(paths()));
        return PromptQualityScreens.TEMPLATES + "status";
    }

    /**
     * The state of quality of the scope.
     *
     * @param scope  the scope of the prompt versions, or none for the platform's
     * @param period the length of the operation periods: day, week (the default), month or quarter
     */
    @ResponseBody
    @GetMapping(API)
    public PromptQualityStatus.Status status(@RequestParam(required = false) String scope,
                                             @RequestParam(required = false) String period,
                                             Authentication authentication) {
        requireAdmin(authentication);
        return status.status(scope, period, tenantOf(scope));
    }

    /**
     * The tenant whose decisions the operation metrics count: the scope's, every tenant's for the platform's scope, as
     * the quality report and the trials read them.
     */
    static String tenantOf(String scope) {
        String name = scope != null && !scope.isBlank() ? scope.trim() : PromptVersionService.PLATFORM_SCOPE;
        return PromptVersionService.PLATFORM_SCOPE.equals(name) ? null : name;
    }

    /**
     * Where the screen's buttons lead: the screens of the group (measure again, the comparison and the result under
     * {@code measure}, the cases to confirm under {@code cases}), the decision records and their review queue, and the
     * quality report.
     */
    public record Paths(String cases, String measure, String versions, String evidence, String decisions,
                        String review, String report) {
    }

    static Paths paths() {
        return new Paths(PromptQualityScreens.CASES, PromptQualityScreens.MEASURE, PromptQualityScreens.VERSIONS,
                PromptQualityScreens.EVIDENCE, DECISIONS, REVIEW_QUEUE, PromptQualityReportController.API);
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value).replace("</", "<\\/");
        }
        catch (JsonProcessingException unwritable) {
            throw new IllegalStateException("The addresses of the quality status could not be written", unwritable);
        }
    }

    static void requireAdmin(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        boolean admin = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch("ROLE_ADMIN"::equals);
        if (!admin) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
    }
}
