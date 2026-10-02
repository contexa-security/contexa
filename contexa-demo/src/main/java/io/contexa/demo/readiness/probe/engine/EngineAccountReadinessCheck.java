package io.contexa.demo.readiness.probe.engine;

import io.contexa.demo.identity.configuration.IdentityProperties;
import io.contexa.demo.identity.repository.NativeIdentitySource;
import io.contexa.demo.identity.service.IdentitySnapshotService;
import io.contexa.demo.readiness.dto.ReadinessCheckResult;
import io.contexa.demo.readiness.probe.AbstractReadinessCheck;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
@Profile("contexa")
public class EngineAccountReadinessCheck extends AbstractReadinessCheck {

    private final NativeIdentitySource source;
    private final IdentitySnapshotService snapshots;
    private final IdentityProperties properties;

    public EngineAccountReadinessCheck(NativeIdentitySource source, IdentitySnapshotService snapshots,
            IdentityProperties properties) {
        super("authentication");
        this.source = source;
        this.snapshots = snapshots;
        this.properties = properties;
    }

    protected List<ReadinessCheckResult> observe() {
        long count = source.load(properties.usernames()).stream().filter(account -> account.enabled()).count();
        var snapshot = snapshots.observation();
        String state = switch (snapshot.state()) {
            case "MATCHED" -> "CONFIGURED_UNVERIFIED";
            case "SOURCE_CHANGED", "BASELINE_CHANGED" -> "INVALID_CONFIGURATION";
            default -> "UNAVAILABLE";
        };
        return List.of(new ReadinessCheckResult("authentication", count > 0 ? "CONFIGURED_UNVERIFIED" : "MISSING",
                        "엔진의 실제 지정 계정입니다. 로그인은 별도 확인합니다.", Map.of("accounts", count)),
                new ReadinessCheckResult("initial-identity", state, "초기 업무 계정의 역할과 상태 비교", snapshot));
    }
}
