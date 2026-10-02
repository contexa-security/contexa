package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.handler.handler.SealedEvidenceCaptureHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.verification.capture.PromptEvidenceMetadataProvider;
import io.contexa.contexacore.verification.capture.SealedEvidenceLayer1CompletionAspect;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptCaptureAspect;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageAssembler;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRetentionScheduler;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PqaSealedEvidenceAutoConfigurationTest {

    private static final List<String> ENTERPRISE_CAPTURE_BEAN_NAMES = List.of(
            "promptEvidenceMetadataProvider",
            "sealedEvidencePromptTraceStore",
            "sealedEvidencePromptCaptureAspect",
            "sealedEvidenceLayer1CompletionAspect",
            "sealedEvidencePackageAssembler",
            "sealedEvidenceCaptureExecutor",
            "sealedEvidenceCaptureHandler");

    private static final List<Class<?>> CAPTURE_TYPES = List.of(
            PromptEvidenceMetadataProvider.class,
            SealedEvidencePromptTraceStore.class,
            SealedEvidencePromptCaptureAspect.class,
            SealedEvidenceLayer1CompletionAspect.class,
            SealedEvidencePackageAssembler.class,
            SealedEvidenceCaptureHandler.class);

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    AopAutoConfiguration.class,
                    PqaSealedEvidenceAutoConfiguration.class))
            .withBean(ObjectMapper.class, ObjectMapper::new)
            .withBean(CanonicalSecurityContextSerializer.class,
                    () -> new CanonicalSecurityContextSerializer(new ObjectMapper()))
            .withBean(SealedEvidencePackageIntegrity.class, SealedEvidencePackageIntegrity::new);

    @Test
    void ossWiresTheRealCaptureChainWithNamesThatDoNotCollideWithEnterprise() {
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    CAPTURE_TYPES.forEach(type -> assertThat(context).hasSingleBean(type));
                    assertThat(context).hasBean("pqaOssSealedEvidenceCaptureExecutor");
                    assertThat(context).hasSingleBean(SealedEvidencePackageRetentionScheduler.class);
                    assertThat(context.getBean(SecurityEventHandler.class).getOrder()).isEqualTo(56);
                    List<String> ossNames = CAPTURE_TYPES.stream()
                            .flatMap(type -> Arrays.stream(context.getBeanNamesForType(type)))
                            .toList();
                    assertThat(ossNames).allMatch(name -> name.startsWith("pqaOss"));
                    assertThat(ossNames).doesNotContainAnyElementsOf(ENTERPRISE_CAPTURE_BEAN_NAMES);
                    assertThat(context.containsBean("sealedEvidenceCaptureExecutor")).isFalse();
                });
    }

    @Test
    void enterpriseEnabledCreatesNoOssCaptureOrRetentionBeans() {
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .withBean("sealedEvidencePromptTraceStore", SealedEvidencePromptTraceStore.class,
                        SealedEvidencePromptTraceStore::new)
                .withPropertyValues("contexa.enterprise.enabled=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBeanNamesForType(SealedEvidencePromptTraceStore.class))
                            .containsExactly("sealedEvidencePromptTraceStore");
                    assertThat(context).doesNotHaveBean(SealedEvidenceCaptureHandler.class);
                    assertThat(context).doesNotHaveBean(SealedEvidencePromptCaptureAspect.class);
                    assertThat(context).doesNotHaveBean(SealedEvidenceLayer1CompletionAspect.class);
                    assertThat(context).doesNotHaveBean(SealedEvidencePackageAssembler.class);
                    assertThat(context).doesNotHaveBean(PromptEvidenceMetadataProvider.class);
                    assertThat(context).doesNotHaveBean("pqaOssSealedEvidenceCaptureExecutor");
                    assertThat(context).doesNotHaveBean(SecurityEventHandler.class);
                    assertThat(context).doesNotHaveBean(SealedEvidencePackageRetentionScheduler.class);
                });
    }

    @Test
    void captureCanBeDisabledWithTheExistingProperty() {
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .withPropertyValues("contexa.pqa.oss.sealed-evidence.capture-enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    CAPTURE_TYPES.forEach(type -> assertThat(context).doesNotHaveBean(type));
                    assertThat(context).doesNotHaveBean("pqaOssSealedEvidenceCaptureExecutor");
                    assertThat(context).hasSingleBean(SealedEvidencePackageRetentionScheduler.class);
                });
    }

    @Test
    void nothingIsWiredWithoutASealedEvidenceRepository() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            CAPTURE_TYPES.forEach(type -> assertThat(context).doesNotHaveBean(type));
            assertThat(context).doesNotHaveBean(SealedEvidencePackageRetentionScheduler.class);
        });
    }

    @Test
    void retentionCleanupCanBeDisabled() {
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .withPropertyValues("contexa.pqa.oss.sealed-evidence.retention.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(SealedEvidencePackageRetentionScheduler.class);
                    assertThat(context).hasSingleBean(SealedEvidenceCaptureHandler.class);
                });
    }

    @Test
    void invalidTraceStoreBoundsFailFast() {
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .withPropertyValues("contexa.pqa.oss.sealed-evidence.max-completed-snapshots=0")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void promptGeneratedThroughTheProxiedGeneratorIsSealedByTheDecisionHandler() {
        SealedEvidencePackageRepository repository = mock(SealedEvidencePackageRepository.class);
        when(repository.findByCorrelationId(any())).thenReturn(Optional.empty());
        runner.withBean(SealedEvidencePackageRepository.class, () -> repository)
                .withBean(PromptGenerator.class, FixedPromptGenerator::new)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    SecurityEvent event = SecurityEvent.builder()
                            .eventId("evt-wiring-001")
                            .userId("alice")
                            .sourceIp("10.0.0.1")
                            .build();
                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("requestId", "req-wiring-001");
                    metadata.put("requestPath", "/api/orders");
                    event.setMetadata(metadata);
                    @SuppressWarnings("unchecked")
                    AIRequest<SecurityDecisionContext> request = mock(AIRequest.class);
                    when(request.getContext()).thenReturn(new SecurityDecisionContext(event, null, null, List.of()));

                    context.getBean(PromptGenerator.class).generatePrompt(request, "context", "metadata");
                    context.getBean(SealedEvidencePromptTraceStore.class).complete(event);
                    SecurityEventContext decision = new SecurityEventContext(event);
                    ProcessingResult result = ProcessingResult.builder().success(true).build();
                    result.setAction("ALLOW");
                    decision.addMetadata("processingResult", result);
                    SecurityEventHandler handler = context.getBean(SecurityEventHandler.class);

                    assertThat(handler.canHandle(decision)).isTrue();
                    assertThat(handler.handle(decision)).isTrue();

                    ArgumentCaptor<SealedEvidencePackage> saved = ArgumentCaptor.forClass(SealedEvidencePackage.class);
                    verify(repository, timeout(5000)).save(saved.capture());
                    assertThat(saved.getValue().getCorrelationId()).isEqualTo("req-wiring-001");
                    assertThat(saved.getValue().getSystemPromptText()).isEqualTo(FixedPromptGenerator.SYSTEM_PROMPT);
                    assertThat(saved.getValue().getUserPromptText()).isEqualTo(FixedPromptGenerator.USER_PROMPT);
                    assertThat(context.getBean(SealedEvidencePackageIntegrity.class).verify(saved.getValue())).isTrue();
                });
    }

    static class FixedPromptGenerator extends PromptGenerator {

        static final String SYSTEM_PROMPT = "fixed system prompt";
        static final String USER_PROMPT = "fixed user prompt";

        FixedPromptGenerator() {
            super(List.of());
        }

        @Override
        public PromptGenerationResult generatePrompt(
                AIRequest<? extends DomainContext> request,
                String contextInfo,
                String systemMetadata) {
            return new PromptGenerationResult(
                    null, SYSTEM_PROMPT, USER_PROMPT, "raw " + SYSTEM_PROMPT, "raw " + USER_PROMPT, Map.of(), null);
        }
    }
}
