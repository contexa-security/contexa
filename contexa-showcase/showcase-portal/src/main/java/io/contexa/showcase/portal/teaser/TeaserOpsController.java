package io.contexa.showcase.portal.teaser;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Operator view of the teaser cards (section 8 of docs/showcase/화면설계서-v2-구현계획.md), on the operator port only
 * (OpsPortConfiguration): which cards' sentences the current records do not make true, so the screens show their
 * fallback, and which cards have no source yet. 404 while live runs are off.
 */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class TeaserOpsController {

    private final ObjectProvider<TeaserService> teasers;

    public TeaserOpsController(ObjectProvider<TeaserService> teasers) {
        this.teasers = teasers;
    }

    @GetMapping("/ops/teasers")
    public ResponseEntity<Map<String, Object>> status() {
        TeaserService service = teasers.getIfAvailable();
        if (service == null) {
            return ResponseEntity.notFound().build();
        }
        TeaserService.View view;
        try {
            view = service.view();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("computedAt", view.computedAt());
        status.put("falseConditions", view.falseConditions());
        status.put("missing", view.teasers().stream().filter(teaser -> teaser.missing() != null)
                .map(teaser -> teaser.key() + ":" + teaser.missing()).toList());
        status.put("teasers", view.teasers());
        return ResponseEntity.ok(status);
    }
}
