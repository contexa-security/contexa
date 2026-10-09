package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The designed cases as frozen (W2-5, docs/showcase/데모-재설계.md 5A.1.3): each case's version, freeze day, ground
 * truth and the SHA-256 of its definition, with the hash of the rule controls the cases are measured against (C1, C2
 * and the role rules, as the business application publishes them). The benchmark states its scope from this.
 */
@RestController
public class CasesController {

    static final Duration RULES_CACHE = Duration.ofMinutes(1);

    /**
     * @param sha256         hash of the case definition, computed as {@link CasesView#canonicalForm} says
     * @param allowedActions the engine actions the case counts as right
     * @param rationale      why the ground truth is what it is, by language
     * @param counterpoint   the expected objection to the ground truth, by language
     */
    public record CaseView(String key, int version, Map<String, String> title, String protagonist,
                           String classification, int steps, LocalDate frozenOn, String sha256,
                           List<String> allowedActions, Map<String, String> rationale,
                           Map<String, String> counterpoint) {
    }

    /** @param sha256 hash the business application publishes for its C1, C2 and role rules (/internal/rules) */
    public record RulesView(String sha256, List<String> covers) {
    }

    public record CasesView(String canonicalForm, RulesView rules, List<CaseView> cases) {

        /** How many cases each ground truth classification has (T-27: counted here, never on the screen). */
        @JsonProperty("classifications")
        public Map<String, Long> classifications() {
            Map<String, Long> counts = new TreeMap<>();
            cases.forEach(row -> counts.merge(String.valueOf(row.classification()), 1L, Long::sum));
            return counts;
        }
    }

    private final ScenarioCatalog catalog;
    private final ObjectProvider<WorkloadAdmin> admin;
    private final Clock clock = Clock.systemUTC();
    private String cachedRules;
    private Instant cachedAt;

    public CasesController(ScenarioCatalog catalog, ObjectProvider<WorkloadAdmin> admin) {
        this.catalog = catalog;
        this.admin = admin;
    }

    /** 503 while the business application that publishes the rules cannot be reached or is not configured. */
    @GetMapping("/api/cases")
    public ResponseEntity<CasesView> cases() {
        WorkloadAdmin workloads = admin.getIfAvailable();
        if (workloads == null) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
        String rules;
        try {
            rules = rulesHash(workloads);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
        List<CaseView> cases = catalog.all().stream()
                .map(scenario -> new CaseView(scenario.key(), scenario.version(), scenario.title(),
                        scenario.protagonist(), scenario.oracle().classification(), scenario.steps().size(),
                        scenario.frozenOn(), catalog.sha256(scenario.key()).orElseThrow(),
                        scenario.oracle().allowedEngineActions(), scenario.oracle().rationale(),
                        scenario.oracle().counterpoint()))
                .toList();
        return ResponseEntity.ok(new CasesView(ScenarioCatalog.CANONICAL_FORM,
                new RulesView(rules, List.of("C1", "C2", "RBAC")), cases));
    }

    private synchronized String rulesHash(WorkloadAdmin workloads) throws IOException {
        Instant now = clock.instant();
        if (cachedRules == null || !now.isBefore(cachedAt.plus(RULES_CACHE))) {
            JsonNode rules = workloads.rules();
            cachedRules = rules.path("sha256").asText(null);
            cachedAt = now;
        }
        return cachedRules;
    }
}
