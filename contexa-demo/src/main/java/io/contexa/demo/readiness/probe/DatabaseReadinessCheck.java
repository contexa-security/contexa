package io.contexa.demo.readiness.probe;

import io.contexa.demo.readiness.dto.ReadinessCheckResult;
import io.contexa.demo.readiness.repository.DiagnosticRepository;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class DatabaseReadinessCheck extends AbstractReadinessCheck {

    private final DiagnosticRepository repository;

    public DatabaseReadinessCheck(DiagnosticRepository repository) {
        super("application-database");
        this.repository = repository;
    }

    protected List<ReadinessCheckResult> observe() {
        return List.of(new ReadinessCheckResult("application-database", "READY", "실제 데이터베이스 연결", repository.database()),
                new ReadinessCheckResult("schema-migrations", "READY", "적용된 데이터 구조 버전", repository.migrations()));
    }
}
