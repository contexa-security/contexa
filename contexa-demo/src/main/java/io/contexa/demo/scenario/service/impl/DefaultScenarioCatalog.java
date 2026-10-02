package io.contexa.demo.scenario.service.impl;

import io.contexa.demo.scenario.dto.ScenarioDeclaration;
import io.contexa.demo.scenario.dto.ScenarioEvaluation;
import io.contexa.demo.scenario.dto.ScenarioSummary;
import io.contexa.demo.scenario.dto.StoredScenario;
import io.contexa.demo.scenario.repository.ScenarioRepository;
import io.contexa.demo.scenario.service.ScenarioCatalog;
import jakarta.validation.Validator;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@Profile("portal")
public class DefaultScenarioCatalog implements ScenarioCatalog {

    private final ScenarioRepository repository;
    private final Validator validator;

    public DefaultScenarioCatalog(ScenarioRepository repository, Validator validator) {
        this.repository = repository;
        this.validator = validator;
    }

    public void register(ScenarioDeclaration declaration) {
        if (!validator.validate(declaration).isEmpty()) {
            throw new IllegalStateException("Invalid scenario declaration");
        }
        if (declaration.oracle().technicalFallbackCountsAsDetection() ||
                declaration.oracle().staticDenialCountsAsDetection()) {
            throw new IllegalStateException("Scenario must preserve attribution boundaries");
        }
        repository.saveVersion(declaration);
    }

    public List<ScenarioSummary> list() {
        return repository.list();
    }

    public StoredScenario find(UUID id) {
        return repository.find(id);
    }

    public ScenarioEvaluation evaluation(UUID id) {
        return repository.evaluation(id);
    }
}
