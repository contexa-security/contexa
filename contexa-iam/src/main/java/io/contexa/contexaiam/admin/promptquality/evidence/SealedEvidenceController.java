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
package io.contexa.contexaiam.admin.promptquality.evidence;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseExpectation;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseGrade;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCaseAnswerForm;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCasePromotionViews;
import io.contexa.contexaiam.admin.promptquality.cases.QualityCasePromotions;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionScreen;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityScreens;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleMessages;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Quality plan 3.7, 3.8: the sealed evidence, the screen that answers what a decision was made from and whether its
 * record is whole: the two sealed prompt screens joined, the list of the sealed decisions with the three checks of the
 * evidence audit and the detail of one, with its replays and the way to make it a labelled case. The inspection again,
 * the inspection of a period and the replay keep their own addresses (PromptInspectionApiController,
 * SealedDecisionReplayApiController), which the screen calls. An administrator's screen, as every screen of the group.
 */
@Controller
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class SealedEvidenceController {

    static final String API = "/contexa/admin/api/prompt-quality/evidence";
    /** The menu entry of the screen (data-menu.sql). */
    static final String ACTIVE_PAGE = "prompt-quality-evidence";
    /** The addresses of the inspection and of the replay, which the screen calls. */
    static final String INSPECTION_API = "/contexa/admin/api/prompt-inspection";
    static final String REPLAY_API = "/contexa/admin/api/sealed-decisions";
    /**
     * The messages the screen reads: its own, the input window of the answer of a case, the period buttons', the
     * console's status words, units, actions and explanations, and the names of the checks a stored result of an
     * earlier inspector names.
     */
    static final String[] MESSAGE_PREFIXES = {"pqa.evidence.", "pqa.answer.", "zt.console.ui.period.",
            "zt.console.ui.status.",
            "zt.console.ui.unit.", "zt.console.ui.action.", "zt.console.ui.decisions.hypothesis.",
            "promptInspection.check.", "promptInspection.verdict.", "promptInspection.trigger."};

    private final JdbcPromptInspectionQueries queries;
    private final SealedEvidenceDetails details;
    private final Supplier<QualityCasePromotions> promotions;
    private final MessageSource messages;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    /**
     * @param promotions   what makes a sealed decision a case; a supplier of null when the cases are not here
     * @param objectMapper Contexa's own JSON writer (the configuration passes it by its name), for the messages of the
     *                     screen
     */
    public SealedEvidenceController(JdbcPromptInspectionQueries queries, SealedEvidenceDetails details,
                                    Supplier<QualityCasePromotions> promotions, MessageSource messages,
                                    @Qualifier("contexaObjectMapper") ObjectMapper objectMapper, Clock clock) {
        this.queries = Objects.requireNonNull(queries, "queries");
        this.details = Objects.requireNonNull(details, "details");
        this.promotions = promotions != null ? promotions : () -> null;
        this.messages = messages;
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    // ----- screens -----

    @GetMapping({PromptQualityScreens.EVIDENCE, PromptQualityScreens.EVIDENCE + "/"})
    public String listPage(Model model, Locale locale, Authentication authentication) {
        return page(null, model, locale, authentication);
    }

    @GetMapping(PromptQualityScreens.EVIDENCE + "/{packageId}")
    public String detailPage(@PathVariable String packageId, Model model, Locale locale,
                             Authentication authentication) {
        return page(packageId, model, locale, authentication);
    }

    private String page(String packageId, Model model, Locale locale, Authentication authentication) {
        requireAdmin(authentication);
        model.addAttribute("screen", "evidence");
        model.addAttribute("activePage", ACTIVE_PAGE);
        model.addAttribute("apiBase", API);
        model.addAttribute("pagesBase", PromptQualityScreens.EVIDENCE);
        model.addAttribute("inspectionApi", INSPECTION_API);
        model.addAttribute("replayApi", REPLAY_API);
        model.addAttribute("packageId", packageId);
        model.addAttribute("scriptMessagesJson", ZeroTrustConsoleMessages.json(messages, locale, objectMapper,
                MESSAGE_PREFIXES));
        return PromptQualityScreens.TEMPLATES + "evidence";
    }

    // ----- reads -----

    /**
     * A page of the sealed decisions of the period that the filter keeps, with the totals of the period.
     *
     * @param from the start of the capture period, or none for 7 days before its end
     * @param to   the end of the capture period, or none for now
     */
    @ResponseBody
    @GetMapping(API)
    public JdbcPromptInspectionQueries.EvidencePage list(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(required = false) String action, @RequestParam(required = false) String version,
            @RequestParam(required = false) String result, @RequestParam(required = false) String user,
            @RequestParam(required = false) String q, @RequestParam(required = false) String block,
            @RequestParam(required = false) String entry, @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = PromptInspectionScreen.DEFAULT_PAGE_SIZE) int size,
            Authentication authentication) {
        requireAdmin(authentication);
        Instant end = to != null ? to : clock.instant();
        Instant start = from != null ? from : end.minus(PromptQualityScreens.SEALED_PERIOD);
        if (end.isBefore(start)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "The period ends before it starts");
        }
        try {
            return queries.evidence(new JdbcPromptInspectionQueries.EvidenceFilter(start, end, action, version, result,
                    user, q, block, entry), page, size);
        }
        catch (IllegalArgumentException refused) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, refused.getMessage());
        }
    }

    /** One sealed decision, inspected again as it is read. */
    @ResponseBody
    @GetMapping(API + "/{packageId}")
    public SealedEvidenceDetails.Detail detail(@PathVariable String packageId, Authentication authentication) {
        requireAdmin(authentication);
        return details.detail(packageId).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    // ----- the case of a sealed decision (quality plan 3.6) -----

    /** Makes the sealed decision a case of the scope; a decision that is not sealed is refused as such. */
    @ResponseBody
    @PostMapping(API + "/{packageId}/case")
    public ResponseEntity<?> promote(@PathVariable String packageId, @RequestParam(required = false) String scope,
                                     @RequestBody QualityCaseAnswerForm answer, Locale locale,
                                     Authentication authentication) {
        requireAdmin(authentication);
        QualityCasePromotions promoting = promotions.get();
        if (promoting == null) {
            return QualityCasePromotionViews.refused(HttpStatus.SERVICE_UNAVAILABLE, "UNAVAILABLE",
                    "The labelled cases are not here");
        }
        QualityCaseExpectation expectation;
        QualityCaseGrade grade;
        try {
            expectation = answer.expectation(locale);
            grade = answer.caseGrade();
        }
        catch (IllegalArgumentException | NullPointerException unreadable) {
            return QualityCasePromotionViews.refused(HttpStatus.BAD_REQUEST, PromptQualityCases.Refusal.INVALID.name(),
                    unreadable.getMessage());
        }
        try {
            return ResponseEntity.ok(QualityCasePromotionViews.Promotion.of(promoting.fromSealed(scope, packageId,
                    expectation, grade, authentication.getName())));
        }
        catch (PromptQualityCases.RefusedException refusal) {
            return QualityCasePromotionViews.refused(refusal);
        }
    }

    private static void requireAdmin(Authentication authentication) {
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
