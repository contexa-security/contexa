package io.contexa.showcase.portal.teaser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Visitor API of the teaser cards' measured values (work 19). The values change only with a new measurement or a new
 * designation, so they are reused for a minute. A card whose sentence a new record makes false is logged once when it
 * turns false (section 8 of docs/showcase/화면설계서-v2-구현계획.md); the operator port lists them ({@code /ops/teasers}).
 */
@RestController
@ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
public class TeaserController {

    static final Duration CACHE = Duration.ofMinutes(1);

    private static final Logger log = LoggerFactory.getLogger(TeaserController.class);

    private final TeaserService teasers;
    private final Clock clock = Clock.systemUTC();
    private TeaserService.View cached;
    private Instant cachedAt;
    private List<String> falseConditions = List.of();

    public TeaserController(TeaserService teasers) {
        this.teasers = teasers;
    }

    @GetMapping("/api/teasers")
    public synchronized ResponseEntity<TeaserService.View> teasers() {
        Instant now = clock.instant();
        if (cached == null || !now.isBefore(cachedAt.plus(CACHE))) {
            try {
                cached = teasers.view();
                cachedAt = now;
                List<String> turnedFalse = cached.falseConditions().stream()
                        .filter(key -> !falseConditions.contains(key)).toList();
                if (!turnedFalse.isEmpty()) {
                    log.error("Teaser sentences no longer hold, the fallback sentences are shown: {}", turnedFalse);
                }
                falseConditions = cached.falseConditions();
            } catch (IOException e) {
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
            }
        }
        return ResponseEntity.ok(cached);
    }
}
