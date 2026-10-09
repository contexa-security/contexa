package io.contexa.showcase.portal.measured;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.regex.Pattern;

/** Visitor API of a case's runs in the current measurement ({@link MeasuredCases}); 404 without one. */
@RestController
@ConditionalOnProperty(name = "showcase.live.enabled", havingValue = "true")
public class MeasuredCasesController {

    /** Shape of a designed case key, checked before any lookup. */
    private static final Pattern CASE_KEY = Pattern.compile("[A-Z][A-Z0-9]{0,7}");

    private final MeasuredCases cases;

    public MeasuredCasesController(MeasuredCases cases) {
        this.cases = cases;
    }

    @GetMapping("/api/cases/{key}/measured")
    public ResponseEntity<MeasuredCases.View> measured(@PathVariable String key) {
        if (!CASE_KEY.matcher(key).matches()) {
            return ResponseEntity.notFound().build();
        }
        return cases.view(key).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }
}
