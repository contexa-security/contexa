package io.contexa.demo.scenario.dto;

import jakarta.validation.constraints.NotEmpty;

import java.util.Map;

public record ScenarioDisplay(@NotEmpty Map<String, String> title) {

}
