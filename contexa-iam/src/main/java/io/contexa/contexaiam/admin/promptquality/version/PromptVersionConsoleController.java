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
package io.contexa.contexaiam.admin.promptquality.version;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentException;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackService;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.AdvancedView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.CheckView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Created;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Draft;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.DraftForm;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.FolderView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.HistoryRow;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ListView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.Receipt;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.ShadowResults;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.TrialStart;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.TrialView;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.UseCheck;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleDtos.VersionView;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleMessages;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;

/**
 * The prompt version screens (plan 3.10): the list, a version, a new version, the trials and the advanced screen, and
 * the JSON they read and send. Every screen and call is an administrator's; every change is a POST, which the console's
 * CSRF protection covers.
 */
@Controller
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PromptVersionConsoleController {

    static final String BASE = "/contexa/admin/prompt-quality/versions";
    static final String API = "/contexa/admin/api/prompt-quality/versions";
    /** The addresses of the release screens the version screens replaced (plan 3.9). */
    static final String RELEASES = "/contexa/admin/prompt-quality/releases";
    /** The menu entry of the screens (data-menu.sql). */
    static final String ACTIVE_PAGE = "prompt-quality-versions";
    /** The messages the screens read: their own and the names of the decision actions. */
    static final String[] MESSAGE_PREFIXES = {"pv.", "zt.console.ui.action.", "zt.console.ui.unit."};
    private static final int SHADOW_DAYS_MAX = 90;

    private final PromptVersionConsole console;
    private final MessageSource messages;
    private final ObjectMapper objectMapper;

    /**
     * @param objectMapper Contexa's own JSON writer (the configuration passes it by its name), for the messages of the
     *                     screens
     */
    public PromptVersionConsoleController(PromptVersionConsole console, MessageSource messages,
                                          @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        this.console = Objects.requireNonNull(console, "console");
        this.messages = messages;
        this.objectMapper = objectMapper;
    }

    // ----- screens -----

    @GetMapping({BASE, BASE + "/"})
    public String listPage(Model model, Locale locale, Authentication authentication) {
        return page("list", model, locale, authentication);
    }

    @GetMapping(BASE + "/{number:\\d+}")
    public String versionPage(@PathVariable int number, Model model, Locale locale, Authentication authentication) {
        model.addAttribute("versionNumber", number);
        return page("version", model, locale, authentication);
    }

    @GetMapping(BASE + "/new")
    public String newPage(Model model, Locale locale, Authentication authentication) {
        return page("new", model, locale, authentication);
    }

    @GetMapping(BASE + "/trials")
    public String trialsPage(Model model, Locale locale, Authentication authentication) {
        return page("trials", model, locale, authentication);
    }

    @GetMapping(BASE + "/trials/{id:\\d+}")
    public String trialPage(@PathVariable long id, Model model, Locale locale, Authentication authentication) {
        model.addAttribute("trialId", id);
        return page("trials", model, locale, authentication);
    }

    @GetMapping(BASE + "/advanced")
    public String advancedPage(Model model, Locale locale, Authentication authentication) {
        return page("advanced", model, locale, authentication);
    }

    // ----- the addresses of the release screens (plan 6-6, 3) -----

    /** The bundle list of the release screens: the versions. */
    @GetMapping({RELEASES, RELEASES + "/"})
    public String releases(@RequestParam(required = false) String registryScope, Authentication authentication) {
        requireAdmin(authentication);
        return "redirect:" + BASE + query(registryScope, null);
    }

    /** A bundle of the release screens: the version of that name, else the versions. */
    @GetMapping(RELEASES + "/detail")
    public String releaseDetail(@RequestParam(required = false) String registryScope,
                                @RequestParam(required = false) String promptKey,
                                @RequestParam(required = false) String promptVersion, Authentication authentication) {
        requireAdmin(authentication);
        OptionalInt number = PromptVersionNames.number(promptVersion);
        return "redirect:" + (number.isPresent() ? BASE + "/" + number.getAsInt() : BASE) + query(registryScope, promptKey);
    }

    /** The comparison of the release screens: the trials, where two versions are compared and the shadow results read. */
    @GetMapping(RELEASES + "/compare")
    public String releaseCompare(@RequestParam(required = false) String registryScope,
                                 @RequestParam(required = false) String promptKey, Authentication authentication) {
        requireAdmin(authentication);
        return "redirect:" + BASE + "/trials" + query(registryScope, promptKey);
    }

    private static String query(String scope, String prompt) {
        UriComponentsBuilder query = UriComponentsBuilder.newInstance();
        if (scope != null && !scope.isBlank()) {
            query.queryParam("scope", scope.trim());
        }
        if (prompt != null && !prompt.isBlank()) {
            query.queryParam("prompt", prompt.trim());
        }
        return query.encode(StandardCharsets.UTF_8).build().toUriString();
    }

    private String page(String screen, Model model, Locale locale, Authentication authentication) {
        requireAdmin(authentication);
        model.addAttribute("screen", screen);
        model.addAttribute("activePage", ACTIVE_PAGE);
        model.addAttribute("apiBase", API);
        model.addAttribute("pagesBase", BASE);
        model.addAttribute("scriptMessagesJson", ZeroTrustConsoleMessages.json(messages, locale, objectMapper,
                MESSAGE_PREFIXES));
        return "contexa/admin/prompt-version/" + screen;
    }

    // ----- reads -----

    @ResponseBody
    @GetMapping(API)
    public ListView list(@RequestParam(required = false) String scope, @RequestParam(required = false) String prompt,
                         @RequestParam(required = false, defaultValue = "false") boolean hidden,
                         Authentication authentication) {
        requireAdmin(authentication);
        return console.list(scope, prompt, hidden);
    }

    @ResponseBody
    @GetMapping(API + "/{number:\\d+}")
    public VersionView version(@PathVariable int number, @RequestParam(required = false) String scope,
                               @RequestParam(required = false) String prompt, Authentication authentication) {
        requireAdmin(authentication);
        return console.version(scope, prompt, number)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    /** Plan 3.6: the version as a document, its changes ({@code diff}, importable) or the whole of it ({@code full}). */
    @GetMapping(API + "/{number:\\d+}/export")
    public ResponseEntity<byte[]> export(@PathVariable int number, @RequestParam(required = false) String scope,
                                         @RequestParam(required = false) String prompt,
                                         @RequestParam(required = false, defaultValue = "diff") String form,
                                         Authentication authentication) {
        requireAdmin(authentication);
        boolean full = "full".equalsIgnoreCase(form);
        if (!full && !"diff".equalsIgnoreCase(form)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "form is diff or full");
        }
        String document = console.export(scope, prompt, number, full)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        String name = console.list(scope, prompt, true).prompt() + "-" + PromptVersionNames.name(number)
                + (full ? "-full" : "") + ".yaml";
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename(name,
                        StandardCharsets.UTF_8).build().toString())
                .contentType(new MediaType("text", "plain", StandardCharsets.UTF_8))
                .body(document.getBytes(StandardCharsets.UTF_8));
    }

    @ResponseBody
    @GetMapping(API + "/draft")
    public Draft draft(@RequestParam(required = false) String scope, @RequestParam(required = false) String prompt,
                       @RequestParam(required = false) Integer base, @RequestParam(required = false) Integer carry,
                       Authentication authentication) {
        requireAdmin(authentication);
        int number = base != null ? base : usedNumber(scope, prompt);
        return console.draft(scope, prompt, number, carry)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @ResponseBody
    @GetMapping(API + "/{number:\\d+}/use-check")
    public UseCheck useCheck(@PathVariable int number, @RequestParam(required = false) String scope,
                             @RequestParam(required = false) String prompt, Authentication authentication) {
        requireAdmin(authentication);
        return console.useCheck(scope, prompt, number);
    }

    @ResponseBody
    @GetMapping(API + "/trials")
    public TrialStart trials(@RequestParam(required = false) String scope, @RequestParam(required = false) String prompt,
                             Authentication authentication) {
        requireAdmin(authentication);
        return console.trials(scope, prompt);
    }

    @ResponseBody
    @GetMapping(API + "/trials/{id:\\d+}")
    public TrialView trial(@PathVariable long id, Authentication authentication) {
        requireAdmin(authentication);
        return console.trial(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @ResponseBody
    @GetMapping(API + "/shadow/results")
    public ShadowResults shadowResults(@RequestParam(required = false) String scope,
                                       @RequestParam(required = false) String prompt,
                                       @RequestParam(required = false, defaultValue = "7") int days,
                                       Authentication authentication) {
        requireAdmin(authentication);
        if (days < 1 || days > SHADOW_DAYS_MAX) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "days is 1 to " + SHADOW_DAYS_MAX);
        }
        Instant to = Instant.now();
        return console.shadowResults(scope, prompt, to.minus(Duration.ofDays(days)), to);
    }

    @ResponseBody
    @GetMapping(API + "/advanced")
    public AdvancedView advanced(@RequestParam(required = false) String scope,
                                 @RequestParam(required = false) String prompt, Authentication authentication) {
        requireAdmin(authentication);
        return console.advanced(scope, prompt);
    }

    @ResponseBody
    @GetMapping(API + "/folder")
    public FolderView folder(@RequestParam(required = false) String scope, @RequestParam(required = false) String prompt,
                             Authentication authentication) {
        requireAdmin(authentication);
        AdvancedView advanced = console.advanced(scope, prompt);
        return advanced.folder();
    }

    @ResponseBody
    @GetMapping(API + "/history")
    public List<HistoryRow> history(@RequestParam(required = false) String scope,
                                    @RequestParam(required = false) String prompt, Authentication authentication) {
        requireAdmin(authentication);
        return console.advanced(scope, prompt).history();
    }

    // ----- writes -----

    @ResponseBody
    @PostMapping(API + "/check")
    public CheckView check(@RequestParam(required = false) String scope, @RequestBody DraftForm form,
                           Authentication authentication) {
        requireAdmin(authentication);
        return console.check(scope, form);
    }

    @ResponseBody
    @PostMapping(API)
    public Created create(@RequestParam(required = false) String scope, @RequestBody DraftForm form,
                          Authentication authentication) {
        requireAdmin(authentication);
        return console.create(scope, form, authentication.getName());
    }

    /** A note of an operator: why a label moved. */
    public record Reason(String reason) {
    }

    @PostMapping(API + "/{number:\\d+}/use")
    public ResponseEntity<Receipt> use(@PathVariable int number, @RequestParam(required = false) String scope,
                                       @RequestParam(required = false) String prompt,
                                       @RequestBody(required = false) Reason body, Authentication authentication) {
        requireAdmin(authentication);
        return receipt(console.use(scope, prompt, number, authentication.getName(), reasonOf(body)));
    }

    @ResponseBody
    @PostMapping(API + "/{number:\\d+}/hide")
    public Map<String, Object> hide(@PathVariable int number, @RequestParam(required = false) String scope,
                                    @RequestParam(required = false) String prompt, Authentication authentication) {
        requireAdmin(authentication);
        console.hide(scope, prompt, number, authentication.getName());
        return Map.of("hidden", PromptVersionNames.name(number));
    }

    /** A document an operator uploads: its file name and its text. */
    public record ImportBody(String fileName, String text) {
    }

    @ResponseBody
    @PostMapping(API + "/import")
    public Created importDocument(@RequestParam(required = false) String scope, @RequestBody ImportBody body,
                                  Authentication authentication) {
        requireAdmin(authentication);
        return console.importDocument(scope, body != null ? body.fileName() : null, body != null ? body.text() : null,
                authentication.getName());
    }

    @ResponseBody
    @PostMapping(API + "/folder/rescan")
    public PromptVersionFolderScanner.Scan rescan(Authentication authentication) {
        requireAdmin(authentication);
        return console.rescan();
    }

    /** A canary: the version, the share of users, the tenants and the address starts or resource IDs it covers. */
    public record CanaryBody(Integer number, Integer percent, String tenants, String paths, String reason) {
    }

    @PostMapping(API + "/canary/start")
    public ResponseEntity<Receipt> startCanary(@RequestParam(required = false) String scope,
                                               @RequestParam(required = false) String prompt,
                                               @RequestBody CanaryBody body, Authentication authentication) {
        requireAdmin(authentication);
        if (body == null || body.number() == null || body.percent() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "number and percent are required");
        }
        return receipt(console.startCanary(scope, prompt, body.number(), body.percent(), body.tenants(), body.paths(),
                authentication.getName(), body.reason()));
    }

    @PostMapping(API + "/canary/stop")
    public ResponseEntity<Receipt> stopCanary(@RequestParam(required = false) String scope,
                                              @RequestParam(required = false) String prompt,
                                              @RequestBody(required = false) Reason body, Authentication authentication) {
        requireAdmin(authentication);
        return receipt(console.stopCanary(scope, prompt, authentication.getName(), reasonOf(body)));
    }

    /** A shadow: the version, the share of requests and the runs a day. */
    public record ShadowBody(Integer number, Integer samplePercent, Integer dailyLimit, String reason) {
    }

    @PostMapping(API + "/shadow/start")
    public ResponseEntity<Receipt> startShadow(@RequestParam(required = false) String scope,
                                               @RequestParam(required = false) String prompt,
                                               @RequestBody ShadowBody body, Authentication authentication) {
        requireAdmin(authentication);
        if (body == null || body.number() == null || body.samplePercent() == null || body.dailyLimit() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "number, samplePercent and dailyLimit are required");
        }
        return receipt(console.startShadow(scope, prompt, body.number(), body.samplePercent(), body.dailyLimit(),
                authentication.getName(), body.reason()));
    }

    @PostMapping(API + "/shadow/stop")
    public ResponseEntity<Receipt> stopShadow(@RequestParam(required = false) String scope,
                                              @RequestParam(required = false) String prompt,
                                              @RequestBody(required = false) Reason body, Authentication authentication) {
        requireAdmin(authentication);
        return receipt(console.stopShadow(scope, prompt, authentication.getName(), reasonOf(body)));
    }

    /** A trial: the version tried, the version it is compared with, and how many sealed decisions. */
    public record TrialBody(Integer candidate, Integer reference, Integer count) {
    }

    @ResponseBody
    @PostMapping(API + "/trials")
    public Map<String, Object> startTrial(@RequestParam(required = false) String scope,
                                          @RequestParam(required = false) String prompt, @RequestBody TrialBody body,
                                          Authentication authentication) {
        requireAdmin(authentication);
        if (body == null || body.candidate() == null || body.reference() == null || body.count() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "candidate, reference and count are required");
        }
        long id = console.startTrial(scope, prompt, body.candidate(), body.reference(), body.count(),
                authentication.getName());
        return Map.of("id", id);
    }

    @ResponseBody
    @PostMapping(API + "/trials/{id:\\d+}/cancel")
    public Map<String, Object> cancelTrial(@PathVariable long id, Authentication authentication) {
        requireAdmin(authentication);
        return Map.of("cancelled", console.cancelTrial(id, authentication.getName()));
    }

    /** An emergency rollback: the version to go back to and why. */
    public record RollbackBody(Integer number, String reason) {
    }

    @PostMapping(API + "/rollback")
    public ResponseEntity<PromptBundleRollbackService.Result> rollback(@RequestParam(required = false) String scope,
                                                                      @RequestParam(required = false) String prompt,
                                                                      @RequestBody RollbackBody body,
                                                                      Authentication authentication) {
        requireAdmin(authentication);
        if (body == null || body.number() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "number is required");
        }
        return rollbackResult(console.emergencyRollback(scope, prompt, body.number(), body.reason(),
                authentication.getName()));
    }

    @PostMapping(API + "/rollback/{executionKey}/approve")
    public ResponseEntity<PromptBundleRollbackService.Result> approve(@PathVariable String executionKey,
                                                                     @RequestParam(required = false) String scope,
                                                                     @RequestParam(required = false) String prompt,
                                                                     Authentication authentication) {
        requireAdmin(authentication);
        return rollbackResult(console.approveRollback(scope, prompt, executionKey, authentication.getName()));
    }

    // ----- answers -----

    /** A request the console refuses: 422 with the code the screen names. */
    @ExceptionHandler(PromptVersionConsole.RefusedException.class)
    public ResponseEntity<Map<String, Object>> refused(PromptVersionConsole.RefusedException refused) {
        return ResponseEntity.unprocessableEntity().body(Map.of("code", refused.code()));
    }

    @ExceptionHandler(PromptVersionTrials.RefusedException.class)
    public ResponseEntity<Map<String, Object>> trialRefused(PromptVersionTrials.RefusedException refused) {
        return ResponseEntity.unprocessableEntity().body(Map.of("code", "TRIAL_" + refused.refusal().name()));
    }

    /** A document that cannot be saved: 422 with every problem (plan 3.5). */
    @ExceptionHandler(PromptVersionDocumentException.class)
    public ResponseEntity<Map<String, Object>> problems(PromptVersionDocumentException refused) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", "PROBLEMS");
        body.put("problems", refused.problems().stream().map(problem -> {
            Map<String, Object> one = new LinkedHashMap<>();
            one.put("code", problem.code().name());
            one.put("where", problem.where());
            one.put("detail", problem.detail());
            return one;
        }).toList());
        return ResponseEntity.unprocessableEntity().body(body);
    }

    private static ResponseEntity<Receipt> receipt(Receipt receipt) {
        return receipt.applied() ? ResponseEntity.ok(receipt) : ResponseEntity.unprocessableEntity().body(receipt);
    }

    private static ResponseEntity<PromptBundleRollbackService.Result> rollbackResult(
            PromptBundleRollbackService.Result result) {
        if (PromptBundleRollbackService.INCOMPLETE.equals(result.status())) {
            return ResponseEntity.badRequest().body(result);
        }
        return PromptBundleRollbackService.REFUSED.equals(result.status())
                ? ResponseEntity.unprocessableEntity().body(result) : ResponseEntity.ok(result);
    }

    private int usedNumber(String scope, String prompt) {
        ListView list = console.list(scope, prompt, false);
        if (list.used() == null || list.used().version() == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return PromptVersionNames.number(list.used().version())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    private static String reasonOf(Reason body) {
        return body != null ? body.reason() : null;
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
