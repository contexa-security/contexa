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

/**
 * The addresses of the sealed prompt screens, which became the sealed evidence (quality plan 3.7, 3.8): the list and
 * a prompt's detail open their place in it, so a bookmark and the links that name them (the decision detail, the
 * trials) keep working. The root address, which was the overview of a period, opens the list. The list's filter comes
 * along: the days of the period, the verdict and the check (the sealed evidence filters by both again), the block, the
 * entry and the page.
 */
@Controller
@RequestMapping("/contexa/admin/prompt-inspection")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PromptInspectionPageController {

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
        keep(target, "verdict", verdict);
        keep(target, "checkCode", checkCode);
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
