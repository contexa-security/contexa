package io.contexa.demo.readiness.probe;

import io.contexa.demo.readiness.dto.ReadinessCheckResult;

import java.util.List;

public abstract class AbstractReadinessCheck implements ReadinessCheck {

    private final String component;

    protected AbstractReadinessCheck(String component) {
        this.component = component;
    }

    public final List<ReadinessCheckResult> inspect() {
        try {
            return observe();
        } catch (RuntimeException unavailable) {
            return List.of(new ReadinessCheckResult(component, "UNAVAILABLE", "점검에 연결하지 못했습니다.",
                    unavailable.getClass().getSimpleName()));
        }
    }

    protected abstract List<ReadinessCheckResult> observe();
}
