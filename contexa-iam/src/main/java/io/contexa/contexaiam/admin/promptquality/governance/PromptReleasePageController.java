package io.contexa.contexaiam.admin.promptquality.governance;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import org.springframework.context.MessageSource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * W7-14: the version screens of the prompt quality console, one purpose each: the bundle list, one bundle's gate with
 * its release and rollback actions, and the comparison of two bundles. The pages draw their data from the version
 * API and read the bundle from the page address; the words their scripts draw come with the page.
 */
@Controller
@RequestMapping("/contexa/admin/prompt-quality/releases")
@PreAuthorize("hasRole('ADMIN')")
public class PromptReleasePageController {

    /** The message keys the version scripts draw. */
    static final List<String> SCRIPT_KEYS = Stream.of(
            PromptReleaseScreen.STATES.stream().map(state -> "promptRelease.state." + state),
            PromptReleaseScreen.BLOCKERS.stream().map(code -> "promptRelease.blocker." + code),
            PromptReleaseScreen.REFUSALS.stream().map(code -> "promptRelease.refusal." + code),
            PromptReleaseScreen.EXECUTIONS.stream().map(status -> "promptRelease.execution." + status),
            PromptReleaseScreen.STAGES.stream().map(stage -> "promptRelease.stage." + stage),
            PromptBundleHashes.ELEMENT_IDS.stream().map(id -> "promptRelease.element." + id),
            Stream.of("state.unknown", "common.loading", "common.empty", "common.error", "common.notFound",
                    "common.yes", "common.no", "gate.ready", "gate.blocked", "gate.none", "gate.unavailable",
                    "gate.applied", "gate.refused", "build.present", "build.absent", "build.hashDiffers",
                    "canary.percent", "canary.tenants", "canary.families", "action.transition", "action.approve",
                    "rollback.executed", "rollback.awaiting", "rollback.approved", "rollback.refused",
                    "rollback.noTargets", "rollback.reasonRequired", "compare.changed", "compare.same",
                    "compare.notInBuild", "compare.cases", "compare.unpaired", "compare.noShadow",
                    "compare.decisionSeal", "compare.shadowSeal", "compare.thisBundle", "compare.otherBundle",
                    "compare.noEvaluation", "evidence.scenarioFamilies")
                    .map(word -> "promptRelease." + word))
            .flatMap(keys -> keys)
            .toList();

    private final MessageSource messages;
    private final ObjectMapper objectMapper;

    public PromptReleasePageController(MessageSource messages, ObjectMapper objectMapper) {
        this.messages = Objects.requireNonNull(messages, "messages");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @GetMapping({"", "/"})
    public String bundles(Model model, Locale locale) {
        return page(model, locale, "bundles", "bundles");
    }

    @GetMapping("/detail")
    public String detail(Model model, Locale locale) {
        return page(model, locale, "bundles", "detail");
    }

    @GetMapping("/compare")
    public String compare(Model model, Locale locale) {
        return page(model, locale, "compare", "compare");
    }

    private String page(Model model, Locale locale, String activeTab, String view) {
        model.addAttribute("activeTab", activeTab);
        model.addAttribute("scriptMessagesJson", scriptMessages(locale));
        model.addAttribute("screenSettingsJson", scriptJson(PromptReleaseScreen.scriptSettings()));
        return "contexa/admin/prompt-release/" + view;
    }

    /** The script words as JSON safe inside a script element. */
    private String scriptMessages(Locale locale) {
        Map<String, String> words = new LinkedHashMap<>();
        for (String key : SCRIPT_KEYS) {
            words.put(key, messages.getMessage(key, null, key, locale));
        }
        return scriptJson(words);
    }

    /** A value as JSON safe inside a script element. */
    private String scriptJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value).replace("</", "<\\/");
        }
        catch (JsonProcessingException exception) {
            throw new IllegalStateException("The version screen script words could not be written", exception);
        }
    }
}
