package io.contexa.demo.scenario.service;

import io.contexa.demo.scenario.dto.ScenarioDeclaration;
import io.contexa.demo.scenario.dto.ScenarioEvaluation;
import io.contexa.demo.scenario.dto.ScenarioSummary;
import io.contexa.demo.scenario.dto.StoredScenario;

import java.util.List;
import java.util.UUID;

public interface ScenarioCatalog {

    void register(ScenarioDeclaration declaration);

    List<ScenarioSummary> list();

    StoredScenario find(UUID id);

    ScenarioEvaluation evaluation(UUID id);
}
