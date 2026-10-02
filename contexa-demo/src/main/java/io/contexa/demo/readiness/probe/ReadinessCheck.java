package io.contexa.demo.readiness.probe;

import io.contexa.demo.readiness.dto.ReadinessCheckResult;

import java.util.List;

public interface ReadinessCheck {

    List<ReadinessCheckResult> inspect();
}
