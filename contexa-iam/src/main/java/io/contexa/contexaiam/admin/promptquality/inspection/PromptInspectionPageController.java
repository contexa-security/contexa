package io.contexa.contexaiam.admin.promptquality.inspection;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.MessageSource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * The inspection screens, one purpose each: the overview of a period, the sealed prompt list, and one prompt's
 * detail. The pages draw their data from the inspection API; the words their scripts draw come with the page.
 */
@Controller
@RequestMapping("/contexa/admin/prompt-inspection")
@PreAuthorize("hasRole('ADMIN')")
public class PromptInspectionPageController {

    /** The message keys the inspection scripts draw. */
    static final List<String> SCRIPT_KEYS = Stream.of(
            PromptInspectionScreen.VERDICTS.stream().map(verdict -> "promptInspection.verdict." + verdict),
            PromptInspectionScreen.CHECKS.stream().map(check -> "promptInspection.check." + check),
            Stream.of("MISMATCH", "UNVERIFIABLE").map(outcome -> "promptInspection.outcome." + outcome),
            Stream.of("AUTO", "OPERATOR").map(trigger -> "promptInspection.trigger." + trigger),
            Stream.of("loading", "empty", "error", "notFound").map(word -> "promptInspection.common." + word),
            Stream.of("total", "previous", "next").map(word -> "promptInspection.packages." + word),
            Stream.of("started", "progress", "done", "failed").map(word -> "promptInspection.reinspect." + word),
            Stream.of("selectLine", "matchedBy", "noFinding", "expected", "actual", "source", "reason", "unplaced",
                            "inspector", "stored.same", "stored.differs", "stored.other", "stored.none",
                            "changes.compared", "changes.disappeared", "changes.appeared", "changes.none")
                    .map(word -> "promptInspection.detail." + word))
            .flatMap(keys -> keys)
            .toList();

    private final MessageSource messages;
    private final ObjectMapper objectMapper;

    public PromptInspectionPageController(MessageSource messages, ObjectMapper objectMapper) {
        this.messages = Objects.requireNonNull(messages, "messages");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @GetMapping({"", "/"})
    public String overview(Model model, Locale locale) {
        return page(model, locale, "overview", "overview");
    }

    @GetMapping("/packages")
    public String packages(Model model, Locale locale) {
        return page(model, locale, "packages", "packages");
    }

    @GetMapping("/packages/{packageId}")
    public String detail(@PathVariable String packageId, Model model, Locale locale) {
        model.addAttribute("packageId", packageId);
        return page(model, locale, "packages", "detail");
    }

    private String page(Model model, Locale locale, String activeTab, String view) {
        model.addAttribute("activeTab", activeTab);
        model.addAttribute("scriptMessagesJson", scriptMessages(locale));
        model.addAttribute("verdicts", PromptInspectionScreen.VERDICTS);
        model.addAttribute("checks", PromptInspectionScreen.CHECKS);
        model.addAttribute("screenSettingsJson", scriptJson(PromptInspectionScreen.scriptSettings()));
        return "contexa/admin/prompt-inspection/" + view;
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
            throw new IllegalStateException("The inspection script words could not be written", exception);
        }
    }
}
