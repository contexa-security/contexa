package io.contexa.demo.experience.factor.controller;

import io.contexa.demo.experience.factor.dto.ComparisonFactor;
import io.contexa.demo.experience.factor.dto.FactorComparison;
import io.contexa.demo.experience.factor.service.FactorComparisonQuery;
import io.contexa.demo.shared.web.AbstractVisitorController;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;
import java.util.UUID;

@RestController
@Profile("portal")
@RequestMapping("/api/lab/factors")
public class FactorComparisonController extends AbstractVisitorController {

    private final FactorComparisonQuery comparisons;

    public FactorComparisonController(FactorComparisonQuery comparisons) {
        this.comparisons = comparisons;
    }

    @GetMapping
    public ResponseEntity<FactorComparison> compare(@RequestParam ComparisonFactor factor,
            @RequestParam List<UUID> before, @RequestParam List<UUID> after, HttpServletRequest request) {
        return result(comparisons.compare(visitorId(request), factor, before, after));
    }
}
