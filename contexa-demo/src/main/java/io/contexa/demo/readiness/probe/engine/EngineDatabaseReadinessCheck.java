package io.contexa.demo.readiness.probe.engine;

import io.contexa.demo.readiness.dto.ReadinessCheckResult;
import io.contexa.demo.readiness.probe.AbstractReadinessCheck;
import io.contexa.demo.readiness.repository.PlatformDiagnosticRepository;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Profile("contexa")
public class EngineDatabaseReadinessCheck extends AbstractReadinessCheck {

    private final PlatformDiagnosticRepository repository;

    public EngineDatabaseReadinessCheck(PlatformDiagnosticRepository repository) {
        super("security-database");
        this.repository = repository;
    }

    protected List<ReadinessCheckResult> observe() {
        var database = repository.database();
        var vectors = repository.vectorExtension();
        return List.of(new ReadinessCheckResult("security-database", "READY", "엔진 전용 데이터베이스 연결", database),
                new ReadinessCheckResult("pgvector", vectors.isEmpty() ? "MISSING" : "READY",
                        "검색 저장소 확장. 모델 차원 호환은 별도 검증합니다.", vectors));
    }
}
