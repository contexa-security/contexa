package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityScreens;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

/**
 * The addresses of the sealed prompt screens, which became the sealed evidence (quality plan 3.7, 3.8): the list and
 * a prompt's detail open their place in it, so a bookmark and the links that name them (the decision detail, the
 * trials) keep working. The root address, which was the overview of a period, opens the list. The list's filter comes
 * along in the words of the sealed evidence: the days of the period, the result (a verdict or a check, as the audit
 * result), the block, the entry and the page.
 */
@Controller
@RequestMapping("/contexa/admin/prompt-inspection")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PromptInspectionPageController {

    /**
     * The message keys the scripts of the sealed prompt screens drew. Their files stay until the table of what moved
     * to the sealed evidence is approved; then they go with these keys.
     */
    static final List<String> SCRIPT_KEYS = Stream.of(
            PromptInspectionScreen.VERDICTS.stream().map(verdict -> "promptInspection.verdict." + verdict),
            Stream.concat(PromptInspectionScreen.CHECKS.stream(), PromptInspectionScreen.RETIRED_CHECKS.stream())
                    .map(check -> "promptInspection.check." + check),
            Stream.of("MISMATCH", "UNVERIFIABLE").map(outcome -> "promptInspection.outcome." + outcome),
            Stream.of("AUTO", "OPERATOR").map(trigger -> "promptInspection.trigger." + trigger),
            Stream.of("loading", "empty", "error", "notFound").map(word -> "promptInspection.common." + word),
            Stream.of("total", "previous", "next").map(word -> "promptInspection.packages." + word),
            Stream.of("started", "progress", "done", "failed").map(word -> "promptInspection.reinspect." + word),
            Stream.of("selectLine", "matchedBy", "noFinding", "expected", "actual", "source", "reason",
                            "reason.earlierBundle", "unplaced",
                            "inspector", "stored.same", "stored.differs", "stored.other", "stored.none",
                            "changes.compared", "changes.disappeared", "changes.appeared", "changes.none")
                    .map(word -> "promptInspection.detail." + word),
            // docs/agent OC-5: the replay section.
            Stream.of("action", "reason", "codes", "model", "elapsed", "baselines", "baselines.GIVEN",
                            "baselines.CURRENT", "integrity", "integrity.VERIFIED", "integrity.MISMATCH",
                            "integrity.UNVERIFIABLE", "failure", "secondPass", "confirm", "running", "failed", "unavailable")
                    .map(word -> "promptInspection.replay." + word))
            .flatMap(keys -> keys)
            .toList();

    /** The audit result of the sealed evidence that a verdict of the sealed prompt list filtered by, or null. */
    static String resultOfVerdict(String verdict) {
        return switch (verdict) {
            case "FAIL" -> "PROBLEM";
            case "INCOMPLETE", "ERROR", JdbcPromptInspectionQueries.NOT_INSPECTED -> "UNCHECKED";
            case "PASS", "NOT_APPLICABLE" -> "WHOLE";
            default -> null;
        };
    }

    /** The audit result of the sealed evidence that a check of the sealed prompt list filtered by, or null. */
    static String resultOfCheck(String checkCode) {
        return switch (checkCode) {
            case "SEAL_INTEGRITY" -> "INTEGRITY";
            case BundleTraceCheck.CODE -> "TRACE";
            case "SOURCE_TRUTH" -> "SOURCE";
            default -> null;
        };
    }

    @GetMapping({"", "/", "/packages"})
    public String list(@RequestParam(required = false) String from, @RequestParam(required = false) String to,
                       @RequestParam(required = false) String verdict,
                       @RequestParam(required = false) String checkCode,
                       @RequestParam(required = false) String block, @RequestParam(required = false) String entry,
                       @RequestParam(required = false) String page) {
        UriComponentsBuilder target = UriComponentsBuilder.fromPath(PromptQualityScreens.EVIDENCE);
        if (StringUtils.hasText(from)) {
            target.queryParam("period", "custom").queryParam("from", from.trim());
            if (StringUtils.hasText(to)) {
                target.queryParam("to", to.trim());
            }
        }
        String result = StringUtils.hasText(checkCode) ? resultOfCheck(checkCode.trim().toUpperCase(Locale.ROOT))
                : null;
        if (result == null && StringUtils.hasText(verdict)) {
            result = resultOfVerdict(verdict.trim().toUpperCase(Locale.ROOT));
        }
        keep(target, "result", result);
        keep(target, "block", block);
        keep(target, "entry", entry);
        keep(target, "page", page);
        return "redirect:" + target.build().encode().toUriString();
    }

    @GetMapping("/packages/{packageId}")
    public String detail(@PathVariable String packageId) {
        return "redirect:" + PromptQualityScreens.EVIDENCE + "/"
                + UriUtils.encodePathSegment(packageId, StandardCharsets.UTF_8);
    }

    private static void keep(UriComponentsBuilder target, String name, String value) {
        if (StringUtils.hasText(value)) {
            target.queryParam(name, value.trim());
        }
    }
}
