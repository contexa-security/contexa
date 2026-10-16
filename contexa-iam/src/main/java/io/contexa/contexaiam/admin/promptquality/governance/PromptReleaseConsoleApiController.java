package io.contexa.contexaiam.admin.promptquality.governance;

import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * W7-14: the read API of the version screens, next to the version query, the transition (W6-8) and the rollback
 * (W6-10) of the same path: the bundle list with the gate's answer, a bundle's gate evidence and the comparison of
 * two bundles. The enterprise integrated management reads the same API.
 */
@RestController
@RequestMapping("/contexa/admin/api/prompt-quality/releases")
@PreAuthorize("hasRole('ADMIN')")
public class PromptReleaseConsoleApiController {

    private final PromptReleaseConsole console;
    private final Clock clock;

    public PromptReleaseConsoleApiController(PromptReleaseConsole console, Clock clock) {
        this.console = Objects.requireNonNull(console, "console");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @GetMapping("/bundles")
    public List<PromptReleaseConsole.BundleRow> bundles(@RequestParam(required = false) String registryScope) {
        return console.bundles(registryScope);
    }

    @GetMapping("/gate")
    public ResponseEntity<PromptReleaseConsole.BundleDetail> gate(
            @RequestParam(required = false) String registryScope,
            @RequestParam String promptKey,
            @RequestParam String promptVersion) {
        return console.detail(registryScope, promptKey, promptVersion).map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** Two bundles of a prompt; the behaviour is read over the capture period (the last seven days unless given). */
    @GetMapping("/compare")
    public PromptReleaseConsole.Comparison compare(
            @RequestParam(required = false) String registryScope,
            @RequestParam String promptKey,
            @RequestParam String base,
            @RequestParam String candidate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to) {
        Instant end = to != null ? to : clock.instant();
        Instant start = from != null ? from : end.minus(PromptReleaseScreen.DEFAULT_PERIOD);
        if (end.isBefore(start)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "The period ends before it starts");
        }
        return console.compare(registryScope, promptKey, base, candidate, start, end);
    }
}
