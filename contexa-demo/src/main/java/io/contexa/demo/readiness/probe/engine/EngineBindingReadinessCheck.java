package io.contexa.demo.readiness.probe.engine;

import io.contexa.contexacore.std.llm.runtime.LlmRuntimeCatalog;
import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.readiness.dto.ReadinessCheckResult;
import io.contexa.demo.readiness.probe.AbstractReadinessCheck;
import io.contexa.demo.readiness.service.EngineObservationQuery;
import io.contexa.demo.readiness.service.RuntimeSecurityQuery;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
@Profile("contexa")
public class EngineBindingReadinessCheck extends AbstractReadinessCheck {

    private static final Set<String> REQUIRED_OBSERVATIONS = Set.of(
            "analysis-listener", "decision-writer", "action-repository", "event-collector", "event-publisher",
            "baseline-store", "security-context-store", "mfa-session-store", "mfa-state-machine",
            "generated-prompt-aspect", "generated-prompt-store", "advisor-registry", "llm-orchestrator",
            "lab-analysis-observer", "lab-model-step-observer", "lab-learning-call-observer",
            "lab-baseline-write-observer", "lab-rag-write-observer", "lab-rag-write-reader",
            "lab-rag-document-query", "lab-provider-interceptor", "lab-provider-customizer",
            "lab-enabled-model-advisor");

    private final ObjectProvider<LlmRuntimeCatalog> catalogs;
    private final RuntimeSecurityQuery security;
    private final LabProperties lab;
    private final EngineObservationQuery observation;

    public EngineBindingReadinessCheck(ObjectProvider<LlmRuntimeCatalog> catalogs,
            RuntimeSecurityQuery security, LabProperties lab, EngineObservationQuery observation) {
        super("engine-bindings");
        this.catalogs = catalogs;
        this.security = security;
        this.lab = lab;
        this.observation = observation;
    }

    protected List<ReadinessCheckResult> observe() {
        var catalog = catalogs.getIfUnique();
        var mode = security.inspect();
        int chat = catalog == null ? 0 : catalog.getChatBindings().size();
        int embedding = catalog == null ? 0 : catalog.getEmbeddingBindings().size();
        var bindings = observation.inspect();
        boolean observationConfigured = REQUIRED_OBSERVATIONS.stream().allMatch(required -> bindings.stream()
                .anyMatch(binding -> required.equals(binding.contract()) && !binding.registeredBeans().isEmpty()
                        && !binding.registeredBeans().containsValue("UNRESOLVED")));
        return List.of(new ReadinessCheckResult("chat", chat == 0 ? "MISSING" : "CONFIGURED_UNVERIFIED",
                        "이 진단은 모델 연결 설정만 확인하며 모델을 호출하지 않습니다.",
                        Map.of("bindings", chat, "provider", String.valueOf(lab.chat().provider()), "model",
                                String.valueOf(lab.chat().model()))),
                new ReadinessCheckResult("embedding", embedding == 0 ? "MISSING" : "CONFIGURED_UNVERIFIED",
                        "검색 모델 설정이며 연결/차원은 실제 실행에서 검증합니다.",
                        Map.of("bindings", embedding, "dimensions", lab.embedding().dimensions())),
                new ReadinessCheckResult("runtime-security",
                        mode.enforcementEnabled() ? "CONFIGURED_UNVERIFIED" : "ENFORCEMENT_DISABLED",
                        "설정은 실제 요청 제어의 증거와 구별합니다.", mode),
                new ReadinessCheckResult("observation-adapter", observationConfigured ? "CONFIGURED_UNVERIFIED" : "MISSING",
                        "필수 관측 연결과 활성 모델 관측기를 확인합니다. 실제 전송·저장 성공은 요청 근거에서 별도로 확인합니다.",
                        bindings));
    }
}
