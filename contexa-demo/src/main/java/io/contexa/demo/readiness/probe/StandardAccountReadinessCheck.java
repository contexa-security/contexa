package io.contexa.demo.readiness.probe;

import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.identity.repository.AccountRepository;
import io.contexa.demo.readiness.dto.ReadinessCheckResult;
import io.contexa.demo.readiness.repository.DiagnosticRepository;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
@Profile("!contexa")
public class StandardAccountReadinessCheck extends AbstractReadinessCheck {

    private final AccountRepository accounts;
    private final DiagnosticRepository diagnostics;
    private final LabProperties lab;

    public StandardAccountReadinessCheck(AccountRepository accounts, DiagnosticRepository diagnostics,
            LabProperties lab) {
        super("authentication");
        this.accounts = accounts;
        this.diagnostics = diagnostics;
        this.lab = lab;
    }

    protected List<ReadinessCheckResult> observe() {
        int count = accounts.enabledCount();
        var result = new ArrayList<ReadinessCheckResult>();
        result.add(new ReadinessCheckResult("authentication", count > 0 ? "CONFIGURED_UNVERIFIED" : "MISSING",
                "등록된 계정 수이며 실제 로그인 검증과는 다릅니다.", Map.of("accounts", count)));
        if ("baseline".equals(lab.role())) {
            var scopes = diagnostics.identityScope();
            result.add(new ReadinessCheckResult("initial-identity",
                    scopes.size() == 1 ? "CONFIGURED_UNVERIFIED" : "MISSING", "지정된 업무 계정의 초기 상태", scopes));
        }
        result.add(new ReadinessCheckResult("runtime-security", "NOT_APPLICABLE", "AI 판단을 사용하지 않는 역할입니다.", null));
        return result;
    }
}
