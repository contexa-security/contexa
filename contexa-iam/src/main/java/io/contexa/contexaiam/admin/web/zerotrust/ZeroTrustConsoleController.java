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
package io.contexa.contexaiam.admin.web.zerotrust;

import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Adoption;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.DecisionDetail;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.DecisionPage;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.DecisionRow;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Evaluation;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.EvaluationSaved;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Impact;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Operations;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Overview;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.ReviewItem;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleDtos.Trust;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
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
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.function.Supplier;

/**
 * The Zero Trust console (console design 4): its seven screens and the JSON they read. Every screen and every call is
 * an administrator's; the evaluation is a POST, so the console's CSRF protection covers it.
 */
@Slf4j
@Controller
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class ZeroTrustConsoleController {

    static final String BASE = "/contexa/admin/zero-trust";
    static final String API = "/contexa/admin/api/zero-trust";

    private final ZeroTrustConsoleService service;
    private final ZeroTrustDecisionRecords records;
    private final MessageSource messages;
    private final ObjectMapper objectMapper;

    /**
     * @param objectMapper Contexa's own JSON writer (the configuration passes it by its name), for the messages of the
     *                     screens
     */
    public ZeroTrustConsoleController(ZeroTrustConsoleService service, ZeroTrustDecisionRecords records,
                                      MessageSource messages,
                                      @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        this.service = service;
        this.records = records;
        this.messages = messages;
        this.objectMapper = objectMapper;
    }

    // ----- screens -----

    @GetMapping({BASE, BASE + "/"})
    public String overviewPage(Model model, Locale locale, Authentication authentication) {
        return page("overview", model, locale, authentication);
    }

    @GetMapping(BASE + "/impact")
    public String impactPage(Model model, Locale locale, Authentication authentication) {
        return page("impact", model, locale, authentication);
    }

    @GetMapping(BASE + "/trust")
    public String trustPage(Model model, Locale locale, Authentication authentication) {
        return page("trust", model, locale, authentication);
    }

    @GetMapping(BASE + "/decisions")
    public String decisionsPage(Model model, Locale locale, Authentication authentication) {
        return page("decisions", model, locale, authentication);
    }

    @GetMapping(BASE + "/decisions/{observationId}")
    public String decisionPage(@PathVariable String observationId, Model model, Locale locale,
                               Authentication authentication) {
        model.addAttribute("observationId", observationId);
        return page("decision", model, locale, authentication);
    }

    /**
     * A request's decision, for the screens that know only the request (the security event log, the blocked users):
     * its detail, else the decision records searched for the request.
     */
    @GetMapping(BASE + "/decisions/request/{requestId}")
    public String decisionOfRequest(@PathVariable String requestId, Authentication authentication) {
        requireAdmin(authentication);
        String observationId = records.observationOfRequest(requestId);
        if (observationId != null) {
            return "redirect:" + BASE + "/decisions/" + UriUtils.encodePathSegment(observationId, StandardCharsets.UTF_8);
        }
        return "redirect:" + BASE + "/decisions?q=" + UriUtils.encodeQueryParam(requestId, StandardCharsets.UTF_8);
    }

    @GetMapping(BASE + "/adoption")
    public String adoptionPage(Model model, Locale locale, Authentication authentication) {
        return page("adoption", model, locale, authentication);
    }

    @GetMapping(BASE + "/operations")
    public String operationsPage(Model model, Locale locale, Authentication authentication) {
        return page("operations", model, locale, authentication);
    }

    // ----- JSON -----

    @ResponseBody
    @GetMapping(API + "/overview")
    public Overview overview(@RequestParam(required = false) String period, @RequestParam(required = false) String from,
                             @RequestParam(required = false) String to, @RequestParam(required = false) String tenant,
                             Locale locale, Authentication authentication) {
        requireAdmin(authentication);
        return within(() -> service.overview(period, from, to, blank(tenant), locale));
    }

    @ResponseBody
    @GetMapping(API + "/impact")
    public Impact impact(@RequestParam(required = false) String period, @RequestParam(required = false) String from,
                         @RequestParam(required = false) String to, @RequestParam(required = false) String tenant,
                         Locale locale, Authentication authentication) {
        requireAdmin(authentication);
        return within(() -> service.impact(period, from, to, blank(tenant), locale));
    }

    @ResponseBody
    @GetMapping(API + "/trust")
    public Trust trust(@RequestParam(required = false) String period, @RequestParam(required = false) String from,
                       @RequestParam(required = false) String to, @RequestParam(required = false) String tenant,
                       Locale locale, Authentication authentication) {
        requireAdmin(authentication);
        return within(() -> service.trust(period, from, to, blank(tenant), locale));
    }

    @ResponseBody
    @GetMapping(API + "/adoption")
    public Adoption adoption(@RequestParam(required = false) String tenant, Locale locale, Authentication authentication) {
        requireAdmin(authentication);
        return service.adoption(blank(tenant), locale);
    }

    @ResponseBody
    @GetMapping(API + "/operations")
    public Operations operations(@RequestParam(required = false) String period,
                                 @RequestParam(required = false) String from, @RequestParam(required = false) String to,
                                 @RequestParam(required = false) String tenant, Locale locale,
                                 Authentication authentication) {
        requireAdmin(authentication);
        return within(() -> service.operations(period, from, to, blank(tenant), locale));
    }

    /**
     * Console plan 5-2 ⑥: a screen's numbers as a CSV (the overview, the threats and work impact, the decision trust,
     * the adoption, the operations), as the AI monitor exported its tabs. The decision records have their own CSV.
     */
    @GetMapping(value = API + "/{screen:overview|impact|trust|adoption|operations}.csv", produces = "text/csv")
    public ResponseEntity<byte[]> screenCsv(@PathVariable String screen, @RequestParam(required = false) String period,
                                            @RequestParam(required = false) String from,
                                            @RequestParam(required = false) String to,
                                            @RequestParam(required = false) String tenant, Locale locale,
                                            Authentication authentication) {
        requireAdmin(authentication);
        String scope = blank(tenant);
        Object answer = within(() -> switch (screen) {
            case "overview" -> service.overview(period, from, to, scope, locale);
            case "impact" -> service.impact(period, from, to, scope, locale);
            case "trust" -> service.trust(period, from, to, scope, locale);
            case "adoption" -> service.adoption(scope, locale);
            default -> service.operations(period, from, to, scope, locale);
        });
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"zero-trust-" + screen + ".csv\"")
                .contentType(new MediaType("text", "csv", StandardCharsets.UTF_8))
                .body(ZeroTrustConsoleCsv.of(answer, objectMapper).getBytes(StandardCharsets.UTF_8));
    }

    @ResponseBody
    @GetMapping(API + "/decisions")
    public DecisionPage decisions(@RequestParam(required = false) String period,
                                  @RequestParam(required = false) String from, @RequestParam(required = false) String to,
                                  @RequestParam(required = false) String tenant,
                                  @RequestParam(required = false) String cursor,
                                  @RequestParam(required = false) String action,
                                  @RequestParam(required = false) String source,
                                  @RequestParam(required = false) String hypothesis,
                                  @RequestParam(required = false) String actor,
                                  @RequestParam(required = false) String resourceClass,
                                  @RequestParam(required = false) String outcome,
                                  @RequestParam(required = false) String mode, @RequestParam(required = false) String q,
                                  @RequestParam(required = false) String order,
                                  Authentication authentication) {
        requireAdmin(authentication);
        ZeroTrustConsoleRange range = within(() -> service.range(period, from, to));
        ZeroTrustDecisionRecords.Filter filter =
                new ZeroTrustDecisionRecords.Filter(action, source, hypothesis, actor, resourceClass, outcome, mode, q);
        // console plan 5-2 ③: the slowest decisions first, one page
        return "slowest".equals(order) ? records.slowest(range, blank(tenant), filter)
                : records.list(range, blank(tenant), filter, cursor);
    }

    @ResponseBody
    @GetMapping(API + "/decisions/{observationId}")
    public ResponseEntity<DecisionDetail> decision(@PathVariable String observationId, Locale locale,
                                                   Authentication authentication) {
        requireAdmin(authentication);
        DecisionDetail detail = records.detail(observationId, locale);
        return detail == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(detail);
    }

    @ResponseBody
    @GetMapping(API + "/review-queue")
    public List<ReviewItem> reviewQueue(Authentication authentication) {
        requireAdmin(authentication);
        return records.reviewQueue();
    }

    /** Console decision 11.3: an administrator's evaluation of a decision, kept as its outcome. */
    @ResponseBody
    @PostMapping(API + "/decisions/{observationId}/evaluation")
    public ResponseEntity<?> evaluate(@PathVariable String observationId, @RequestBody Evaluation evaluation,
                                      Authentication authentication) {
        requireAdmin(authentication);
        try {
            EvaluationSaved saved = records.evaluate(observationId, evaluation, authentication.getName());
            return saved == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(saved);
        } catch (IllegalArgumentException invalid) {
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, invalid.getMessage());
            problem.setProperty("code", "INVALID_EVALUATION");
            return ResponseEntity.badRequest().body(problem);
        }
    }

    /** The decision list of the period and filters, as CSV (at most {@link ZeroTrustDecisionRecords#CSV_LIMIT} rows). */
    @GetMapping(value = API + "/decisions.csv", produces = "text/csv")
    public ResponseEntity<byte[]> decisionsCsv(@RequestParam(required = false) String period,
                                               @RequestParam(required = false) String from,
                                               @RequestParam(required = false) String to,
                                               @RequestParam(required = false) String tenant,
                                               @RequestParam(required = false) String action,
                                               @RequestParam(required = false) String source,
                                               @RequestParam(required = false) String hypothesis,
                                               @RequestParam(required = false) String actor,
                                               @RequestParam(required = false) String resourceClass,
                                               @RequestParam(required = false) String outcome,
                                               @RequestParam(required = false) String mode,
                                               @RequestParam(required = false) String q,
                                               Authentication authentication) {
        requireAdmin(authentication);
        ZeroTrustConsoleRange range = within(() -> service.range(period, from, to));
        List<DecisionRow> rows = records.export(range, blank(tenant),
                new ZeroTrustDecisionRecords.Filter(action, source, hypothesis, actor, resourceClass, outcome, mode, q));
        StringBuilder csv = new StringBuilder("﻿time,user,resource,method,resource_class,action,source,hypothesis,"
                + "first_reason,reason_group,outcome,total_ms,mode,actor,observation_id\n");
        for (DecisionRow row : rows) {
            csv.append(String.join(",", cell(row.createdAt()), cell(row.user()), cell(row.resource()), cell(row.method()),
                    cell(row.resourceClass()), cell(row.action()), cell(row.source()), cell(row.hypothesis()),
                    cell(row.firstReason()), cell(row.firstReasonGroup()), cell(row.outcome()),
                    cell(row.totalMs() == null ? null : String.valueOf(row.totalMs())), cell(row.mode()),
                    cell(row.actor()), cell(row.observationId()))).append('\n');
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"zero-trust-decisions.csv\"")
                .contentType(new MediaType("text", "csv", StandardCharsets.UTF_8))
                .body(csv.toString().getBytes(StandardCharsets.UTF_8));
    }

    // ----- helpers -----

    private String page(String screen, Model model, Locale locale, Authentication authentication) {
        requireAdmin(authentication);
        model.addAttribute("screen", screen);
        // the menu of the screen (data-menu.sql); a decision's detail belongs to the decision records
        model.addAttribute("activePage", "zero-trust-" + ("decision".equals(screen) ? "decisions" : screen));
        model.addAttribute("apiBase", API);
        model.addAttribute("scriptMessagesJson", ZeroTrustConsoleMessages.json(messages, locale, objectMapper));
        return "contexa/admin/zero-trust/" + screen;
    }

    /** A period the operator gave that cannot be read is a 400, not a server error. */
    private static <T> T within(Supplier<T> read) {
        try {
            return read.get();
        } catch (IllegalArgumentException invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, invalid.getMessage());
        }
    }

    /** A CSV cell: quoted when it holds a separator, and a formula sign is defused (CSV injection). */
    static String cell(String value) {
        if (value == null) {
            return "";
        }
        String text = value;
        if (!text.isEmpty() && "=+-@\t\r".indexOf(text.charAt(0)) >= 0) {
            text = "'" + text;
        }
        if (text.contains(",") || text.contains("\"") || text.contains("\n") || text.contains("\r")) {
            return "\"" + text.replace("\"", "\"\"") + "\"";
        }
        return text;
    }

    private static String blank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
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
