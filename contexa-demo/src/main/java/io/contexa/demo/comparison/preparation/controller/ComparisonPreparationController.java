package io.contexa.demo.comparison.preparation.controller;

import io.contexa.demo.comparison.preparation.dto.PreparationCommand;
import io.contexa.demo.comparison.preparation.dto.PreparedComparison;
import io.contexa.demo.comparison.preparation.service.ComparisonPreparationService;
import io.contexa.demo.shared.web.AbstractVisitorController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@Profile("portal")
@RequestMapping("/api/lab/comparisons/preparations")
public class ComparisonPreparationController extends AbstractVisitorController {

    private final ComparisonPreparationService preparations;

    public ComparisonPreparationController(ComparisonPreparationService preparations) {
        this.preparations = preparations;
    }

    @PostMapping
    public ResponseEntity<PreparedComparison> prepare(@Valid @RequestBody PreparationCommand command,
            HttpServletRequest request) {
        return result(preparations.prepare(visitorId(request), command));
    }

    @GetMapping("/{id}")
    public ResponseEntity<PreparedComparison> find(@PathVariable UUID id, HttpServletRequest request) {
        return result(preparations.find(visitorId(request), id));
    }
}
