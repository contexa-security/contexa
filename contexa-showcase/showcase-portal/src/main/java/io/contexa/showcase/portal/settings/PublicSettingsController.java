package io.contexa.showcase.portal.settings;

import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import io.contexa.showcase.portal.retention.RetentionJob;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Visitor API of the demo's real settings (G3's settings window, the adoption screen). The workloads' published values
 * change only with a new build, so they are read again at most every minute. The values are the workloads' own, so the
 * API exists where the portal reaches them (the orchestration part, ADR-20).
 */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.controls", name = "d")
public class PublicSettingsController {

    static final Duration CACHE = Duration.ofMinutes(1);

    private static final Logger log = LoggerFactory.getLogger(PublicSettingsController.class);

    private final WorkloadAdmin admin;
    private final PublicSettings.Waf waf;
    private final int promptOriginalDays = (int) RetentionJob.Periods.plan().modelExchange().toDays();
    private final Clock clock = Clock.systemUTC();
    private PublicSettings.View cached;
    private Instant cachedAt;

    public PublicSettingsController(WorkloadAdmin admin,
                                    @Value("${showcase.controls.waf.image:#{null}}") String wafImage,
                                    @Value("${showcase.controls.waf.rule-set:#{null}}") String wafRuleSet) {
        this.admin = admin;
        this.waf = new PublicSettings.Waf(wafImage, wafRuleSet);
    }

    @GetMapping("/api/settings")
    public synchronized ResponseEntity<PublicSettings.View> settings() {
        Instant now = clock.instant();
        if (cached == null || !now.isBefore(cachedAt.plus(CACHE))) {
            try {
                cached = PublicSettings.of(admin.rules(), admin.engine(), waf, promptOriginalDays);
                cachedAt = now;
            } catch (IOException | RuntimeException e) {
                log.error("The published settings could not be read", e);
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
            }
        }
        return ResponseEntity.ok(cached);
    }
}
