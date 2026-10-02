package io.contexa.demo.readiness.service.engine;

import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import io.contexa.contexacore.autonomous.event.SecurityEventCollector;
import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.statemachine.core.service.MfaStateMachineService;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventObserver;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.monitoring.ai.AiSecurityDecisionObservationWriter;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import io.contexa.contexacore.std.llm.client.UnifiedLLMOrchestrator;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptCaptureAspect;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import io.contexa.demo.readiness.dto.EngineObservationBinding;
import io.contexa.demo.readiness.service.EngineObservationQuery;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.session.SessionRepository;

import java.util.List;
import java.util.TreeMap;

@Component
@Profile("contexa")
public class ContexaEngineObservationQuery implements EngineObservationQuery {

    private final ListableBeanFactory beans;

    public ContexaEngineObservationQuery(ListableBeanFactory beans) {
        this.beans = beans;
    }

    @Override
    public List<EngineObservationBinding> inspect() {
        return List.of(
                binding("analysis-listener", LlmAnalysisEventListener.class),
                binding("analysis-observer", LlmAnalysisEventObserver.class),
                binding("decision-writer", AiSecurityDecisionObservationWriter.class),
                binding("action-repository", ZeroTrustActionRepository.class),
                binding("event-collector", SecurityEventCollector.class),
                binding("event-publisher", SecurityEventPublisher.class),
                binding("baseline-store", BaselineDataStore.class),
                binding("security-context-store", SecurityContextDataStore.class),
                binding("mfa-session-store", MfaSessionRepository.class),
                binding("mfa-state-machine", MfaStateMachineService.class),
                binding("http-session-store", SessionRepository.class),
                binding("generated-prompt-aspect", SealedEvidencePromptCaptureAspect.class),
                binding("generated-prompt-store", SealedEvidencePromptTraceStore.class),
                binding("advisor-registry", AdvisorRegistry.class),
                binding("llm-orchestrator", UnifiedLLMOrchestrator.class),
                namedBinding("lab-analysis-observer", "nativeAnalysisObserver"),
                namedBinding("lab-model-step-observer", "nativeModelStepObservationAspect"),
                namedBinding("lab-learning-call-observer", "nativeLearningCallObservationAspect"),
                namedBinding("lab-baseline-write-observer", "nativeBaselineWriteObservationAspect"),
                namedBinding("lab-rag-write-observer", "nativeRagWriteObservationAspect"),
                namedBinding("lab-rag-write-reader", "nativeRagWriteObservationEnricher"),
                namedBinding("lab-rag-document-query", "nativeRagDocumentQuery"),
                namedBinding("lab-provider-interceptor", "providerObservationInterceptor"),
                namedBinding("lab-provider-customizer", "providerObservationCustomizer"),
                enabledModelAdvisor());
    }

    private EngineObservationBinding namedBinding(String contract, String beanName) {
        var registered = new TreeMap<String, String>();
        if (beans.containsBean(beanName)) {
            Class<?> implementation = beans.getType(beanName, false);
            registered.put(beanName, implementation == null ? "UNRESOLVED" : implementation.getName());
        }
        return new EngineObservationBinding(contract, registered);
    }

    private EngineObservationBinding enabledModelAdvisor() {
        var registered = new TreeMap<String, String>();
        String[] names = beans.getBeanNamesForType(AdvisorRegistry.class, true, false);
        if (names.length == 1) {
            var registry = beans.getBean(names[0], AdvisorRegistry.class);
            registry.getEnabled().stream()
                    .filter(advisor -> "lab-observation.model-boundary".equals(advisor.getName()))
                    .forEach(advisor -> registered.put(advisor.getName(), advisor.getClass().getName()));
        }
        return new EngineObservationBinding("lab-enabled-model-advisor", registered);
    }

    private EngineObservationBinding binding(String contract, Class<?> type) {
        var registered = new TreeMap<String, String>();
        for (String name : beans.getBeanNamesForType(type, true, false)) {
            Class<?> implementation = beans.getType(name, false);
            registered.put(name, implementation == null ? "UNRESOLVED" : implementation.getName());
        }
        return new EngineObservationBinding(contract, registered);
    }
}
