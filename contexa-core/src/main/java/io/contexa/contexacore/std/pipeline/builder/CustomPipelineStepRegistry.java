package io.contexa.contexacore.std.pipeline.builder;

import io.contexa.contexacore.std.pipeline.step.PipelineStep;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

@Slf4j
public class CustomPipelineStepRegistry {

    private final Map<String, PipelineStep> customSteps = new ConcurrentHashMap<>();

    public void registerCustomStep(String stepName, PipelineStep step) {
        if (stepName == null || stepName.trim().isEmpty()) {
            throw new IllegalArgumentException("Step name cannot be null or empty");
        }
        if (step == null) {
            throw new IllegalArgumentException("Step cannot be null");
        }

        customSteps.put(stepName, step);
            }

    public Optional<PipelineStep> getCustomStep(String stepName) {
        return Optional.ofNullable(customSteps.get(stepName));
    }

    public int getCustomStepCount() {
        return customSteps.size();
    }

    public boolean hasCustomStep(String stepName) {
        return customSteps.containsKey(stepName);
    }

    public Map<String, PipelineStep> getAllCustomSteps() {
        return Map.copyOf(customSteps);
    }

    public boolean removeCustomStep(String stepName) {
        boolean removed = customSteps.remove(stepName) != null;
        if (removed) {
                    }
        return removed;
    }

    public void clearAllCustomSteps() {
        int count = customSteps.size();
        customSteps.clear();
            }
}
