package io.contexa.demo.readiness.service;

import io.contexa.demo.readiness.dto.ReadinessCapture;
import io.contexa.demo.readiness.dto.ReadinessReport;
import io.contexa.demo.readiness.dto.StoredReadiness;

import java.util.List;

public interface ReadinessService {

    ReadinessReport inspect(boolean details, boolean aggregate);

    ReadinessCapture capture();

    List<StoredReadiness> history();
}
