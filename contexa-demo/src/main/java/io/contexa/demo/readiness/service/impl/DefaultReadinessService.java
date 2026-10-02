package io.contexa.demo.readiness.service.impl;

import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.readiness.client.WorkerReadinessClient;
import io.contexa.demo.readiness.dto.ReadinessCapture;
import io.contexa.demo.readiness.dto.ReadinessCheckResult;
import io.contexa.demo.readiness.dto.ReadinessReport;
import io.contexa.demo.readiness.dto.StoredReadiness;
import io.contexa.demo.readiness.dto.WorkerReadiness;
import io.contexa.demo.readiness.probe.ReadinessCheck;
import io.contexa.demo.readiness.repository.ReadinessHistoryRepository;
import io.contexa.demo.readiness.service.ReadinessService;
import io.contexa.demo.readiness.service.RuntimeSecurityQuery;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Service
public class DefaultReadinessService implements ReadinessService {

    private final List<ReadinessCheck> checks;
    private final WorkerReadinessClient workers;
    private final ReadinessHistoryRepository history;
    private final LabProperties lab;
    private final RuntimeSecurityQuery security;

    public DefaultReadinessService(List<ReadinessCheck> checks, WorkerReadinessClient workers,
            ReadinessHistoryRepository history, LabProperties lab, RuntimeSecurityQuery security) {
        this.checks = checks;
        this.workers = workers;
        this.history = history;
        this.lab = lab;
        this.security = security;
    }

    public ReadinessReport inspect(boolean details, boolean aggregate) {
        var observations = new ArrayList<>(checks.stream().flatMap(check -> check.inspect().stream()).toList());
        observations.add(
                new ReadinessCheckResult("experiment-runner", "PARTIALLY_IMPLEMENTED",
                        "문서 1회 비교 실행을 연결했습니다. 전체 조건 고정과 완료 검수는 진행 중입니다.", null));
        List<WorkerReadiness> remote = List.of();
        if (aggregate && "portal".equals(lab.role())) {
            var baseline = workers.inspect("baseline", lab.endpoints().baseline());
            var contexa = workers.inspect("contexa", lab.endpoints().contexa());
            remote = List.of(baseline.join(), contexa.join());
        }
        boolean ready = observations.stream().noneMatch(
                check -> Set.of("MISSING", "UNAVAILABLE", "INVALID_CONFIGURATION", "ENFORCEMENT_DISABLED")
                        .contains(check.state()))
                && remote.stream()
                .allMatch(worker -> "REACHABLE".equals(worker.state()) && worker.report().foundationReady());
        var visible = details ? List.copyOf(observations) : observations.stream()
                .map(check -> new ReadinessCheckResult(check.component(), check.state(), null, null)).toList();
        return new ReadinessReport(lab.role(), Instant.now(), ready, false, false, security.inspect(), visible, remote);
    }

    public ReadinessCapture capture() {
        var report = inspect(false, true);
        return new ReadinessCapture(history.save(report), report);
    }

    public List<StoredReadiness> history() {
        return history.history();
    }
}
