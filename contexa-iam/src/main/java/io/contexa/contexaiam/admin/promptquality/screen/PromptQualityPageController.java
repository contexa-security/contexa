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
package io.contexa.contexaiam.admin.promptquality.screen;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Tab;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.View;
import io.contexa.contexaiam.admin.web.zerotrust.ZeroTrustConsoleMessages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.lang.Nullable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * The screens of the labelled cases (quality plan 3.2) and of measure and compare (quality plan 3.3, 3.8): the frame of
 * each view, its title, the question it answers, the menu bar of the group, the addresses its script reads and the
 * words it shows. The views of a screen are drawn by its script from the screen's JSON. Every screen is an
 * administrator's, as the prompt version screens are.
 */
@Controller
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PromptQualityPageController {

    private static final Logger log = LoggerFactory.getLogger(PromptQualityPageController.class);

    /**
     * Quality plan 3.5: the count beside the tab of a view that the menu bar does not count (the wrong answers of the
     * view of the causes), for the scope and the measurement of the page; null for none.
     */
    @FunctionalInterface
    public interface ViewCounts {

        @Nullable
        Long count(String view, @Nullable String scope, @Nullable Long measureId);
    }

    /** The JSON of the labelled cases. */
    static final String CASES_API = "/contexa/admin/api/prompt-quality/cases";
    /** The JSON of measure and compare. */
    static final String MEASURE_API = "/contexa/admin/api/prompt-quality/measure";
    /** The JSON of the prompt versions, which the trials, the confirmation of "use for decisions" and the canary read. */
    static final String VERSIONS_API = "/contexa/admin/api/prompt-quality/versions";
    /** The path of the views of one measurement: the latest finished one, or the one of the page. */
    static final String RUN = "/run";
    /**
     * The words the scripts of the screens read: their own, the version screens' (the trials, the confirmation and
     * the notices they share), the decision actions, the units, the filter box's and the reason codes an answer cites.
     * K197: the words the decision detail of the console reads the codes of a decision input by (a login, an action,
     * an operating system, a network zone, a record state) and the names of the facts, for the input of a case.
     */
    static final String[] MESSAGE_PREFIXES = {"pqa.", "pv.", "zt.console.ui.action.", "zt.console.ui.unit.",
            "zt.console.ui.decisions.filter", "zt.console.reasonCode.", "zt.console.ui.decision.value.",
            "zt.console.fact."};

    private final MessageSource messages;
    private final ObjectMapper objectMapper;
    @Nullable
    private final ViewCounts viewCounts;

    /** @param objectMapper Contexa's own JSON writer, for the words of the screens */
    public PromptQualityPageController(MessageSource messages,
                                       @Qualifier("contexaObjectMapper") ObjectMapper objectMapper) {
        this(messages, objectMapper, null);
    }

    /** @param viewCounts the counts beside the tabs of the views the menu bar does not count, or null for none */
    public PromptQualityPageController(MessageSource messages,
                                       @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
                                       @Nullable ViewCounts viewCounts) {
        this.messages = messages;
        this.objectMapper = objectMapper;
        this.viewCounts = viewCounts;
    }

    // ----- the labelled cases -----

    @GetMapping({PromptQualityScreens.CASES, PromptQualityScreens.CASES + "/"})
    public String casesPage(Model model, Locale locale, Authentication authentication) {
        return page("cases", "list", model, locale, authentication);
    }

    @GetMapping(PromptQualityScreens.CASES + "/{key:[A-Za-z0-9._-]+}")
    public String casePage(@PathVariable String key, Model model, Locale locale, Authentication authentication) {
        model.addAttribute("caseKey", key);
        return page("cases", "detail", model, locale, authentication);
    }

    // ----- measure and compare -----

    /** The list and the start; the start opens with the version asked (the "measure" button of the version screens). */
    @GetMapping({PromptQualityScreens.MEASURE, PromptQualityScreens.MEASURE + "/"})
    public String measurePage(@RequestParam(required = false) Integer candidate,
                              @RequestParam(required = false) String view, Model model, Locale locale,
                              Authentication authentication) {
        model.addAttribute("candidate", candidate);
        return page("measure", chosen(view, "runs"), model, locale, authentication);
    }

    /** One measurement: the latest finished one of the scope. */
    @GetMapping(PromptQualityScreens.MEASURE + "/run")
    public String latestRunPage(@RequestParam(required = false) String view, Model model, Locale locale,
                                Authentication authentication) {
        return page("measure", chosen(view, "run"), model, locale, authentication);
    }

    @GetMapping(PromptQualityScreens.MEASURE + "/{id:\\d+}")
    public String runPage(@PathVariable long id, @RequestParam(required = false) String view, Model model,
                          Locale locale, Authentication authentication) {
        model.addAttribute("measureId", id);
        return page("measure", chosen(view, "run"), model, locale, authentication);
    }

    /**
     * Two versions: the candidate and the version it is compared with (the reference, as the confirmation of "use for
     * decisions" links here), else the latest candidate measured and the version in use; or two measurements by their
     * ids (candidateMeasure, referenceMeasure: a version measured twice), which win when both are given.
     */
    @GetMapping(PromptQualityScreens.MEASURE + "/compare")
    public String comparePage(@RequestParam(required = false) Integer candidate,
                              @RequestParam(required = false) Integer reference,
                              @RequestParam(required = false) Long candidateMeasure,
                              @RequestParam(required = false) Long referenceMeasure,
                              @RequestParam(required = false) String view, Model model, Locale locale,
                              Authentication authentication) {
        model.addAttribute("candidate", candidate);
        model.addAttribute("reference", reference);
        model.addAttribute("candidateMeasure", candidateMeasure);
        model.addAttribute("referenceMeasure", referenceMeasure);
        return page("measure", chosen(view, "compare"), model, locale, authentication);
    }

    /** The result of a measurement on the latest sealed decisions: a trial of the prompt versions (plan 3.10). */
    @GetMapping(PromptQualityScreens.MEASURE + "/trials/{id:\\d+}")
    public String trialPage(@PathVariable long id, Model model, Locale locale, Authentication authentication) {
        model.addAttribute("trialId", id);
        return page("measure", "trial", model, locale, authentication);
    }

    /**
     * The view the query names (view=...), when it is one of the views of measure and compare
     * (PromptQualityMeasureScreen.VIEWS), else the page's own: a view another bundle adds is opened by its name, and a
     * name this installation does not know opens the page's own view.
     */
    static String chosen(@Nullable String asked, String own) {
        return asked != null && PromptQualityMeasureScreen.VIEWS.stream().anyMatch(one -> one.key().equals(asked.trim()))
                ? asked.trim() : own;
    }

    /** The screen's template; its menu entry (data-menu.sql) is "prompt-quality-" and the screen's name. */
    private String page(String screen, String view, Model model, Locale locale, Authentication authentication) {
        requireAdmin(authentication);
        model.addAttribute("screen", screen);
        model.addAttribute("view", view);
        model.addAttribute("activePage", "prompt-quality-" + screen);
        model.addAttribute("apiBase", "cases".equals(screen) ? CASES_API : MEASURE_API);
        model.addAttribute("versionsApi", VERSIONS_API);
        model.addAttribute("versionsPages", PromptQualityScreens.VERSIONS);
        model.addAttribute("measureBase", PromptQualityScreens.MEASURE);
        model.addAttribute("scriptMessagesJson", ZeroTrustConsoleMessages.json(messages, locale, objectMapper,
                MESSAGE_PREFIXES));
        if ("measure".equals(screen)) {
            Object nav = model.getAttribute(PromptQualityNavAdvice.ATTRIBUTE);
            Object measureId = model.getAttribute("measureId");
            model.addAttribute("measureTabs", tabs(view, nav instanceof PromptQualityNav bar ? bar : null, locale,
                    measureId instanceof Long id ? id : null));
            model.addAttribute("viewScripts", PromptQualityMeasureScreen.VIEWS.stream().map(View::script)
                    .filter(Objects::nonNull).distinct().toList());
        }
        return PromptQualityScreens.TEMPLATES + screen;
    }

    /**
     * The tab bar of the views of measure and compare (PromptQualityMeasureScreen.VIEWS), the page's own lit; a count
     * beside a name is the menu bar's count of the same thing, so the two never differ. On the page of one measurement
     * the views of a measurement (their path under {@code /run}) open on that measurement.
     *
     * @param measureId the measurement of the page, or null
     */
    List<Tab> tabs(String view, @Nullable PromptQualityNav bar, Locale locale, @Nullable Long measureId) {
        String scope = bar != null ? bar.scope() : null;
        List<Tab> tabs = new ArrayList<>();
        for (View one : PromptQualityMeasureScreen.VIEWS) {
            String name = messages.getMessage(one.label(), null, one.label(), locale);
            String count = null;
            if (one.count() != null && bar != null) {
                String menu = PromptQualityScreens.MENUS.stream().filter(entry -> entry.count() == one.count())
                        .map(PromptQualityScreens.Menu::key).findFirst().orElse(null);
                count = bar.tabs().stream().filter(tab -> tab.key().equals(menu) && tab.shortCount() != null)
                        .map(PromptQualityNav.Tab::shortCount).findFirst().orElse(null);
            }
            else if (one.count() == null && viewCounts != null) {
                count = viewCount(one.key(), scope, measureId, locale);
            }
            String text = count != null ? messages.getMessage("pqa.cases.tabCount", new Object[] {name, count},
                    name + " " + count, locale) : name;
            String path = measureId != null && (one.path().equals(RUN) || one.path().startsWith(RUN + "?"))
                    ? "/" + measureId + one.path().substring(RUN.length()) : one.path();
            tabs.add(new Tab(one.key(), href(path, scope), text, one.lit(view)));
        }
        return List.copyOf(tabs);
    }

    /** A view's own count beside its tab; a count that cannot be read leaves the tab without one. */
    @Nullable
    private String viewCount(String view, @Nullable String scope, @Nullable Long measureId, Locale locale) {
        try {
            Long count = viewCounts.count(view, scope, measureId);
            return count != null ? NumberFormat.getIntegerInstance(locale).format(count) : null;
        }
        catch (RuntimeException unreadable) {
            log.error("[PromptQualityScreen] The count beside the tab of the view {} could not be read", view,
                    unreadable);
            return null;
        }
    }

    /** The address of a view with the scope of the page; a view's path may carry its query (/run?view=causes). */
    static String href(String path, @Nullable String scope) {
        UriComponentsBuilder href = UriComponentsBuilder.fromUriString(PromptQualityScreens.MEASURE + path);
        if (scope != null) {
            href.queryParam("scope", scope);
        }
        return href.encode(StandardCharsets.UTF_8).build().toUriString();
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
