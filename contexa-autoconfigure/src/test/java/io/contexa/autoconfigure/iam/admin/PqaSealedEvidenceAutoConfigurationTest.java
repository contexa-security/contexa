package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import io.contexa.contexacore.autonomous.handler.handler.SealedEvidenceCaptureHandler;
import io.contexa.contexacore.autonomous.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.processor.PromptShadowRunner;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionContext;
import io.contexa.contexacore.std.components.prompt.PromptGenerationResult;
import io.contexa.contexacore.std.components.prompt.PromptGenerator;
import io.contexa.contexacore.verification.capture.SealedEvidenceLayer1CompletionAspect;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptCaptureAspect;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidenceCaptureSampling;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageAssembler;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRetentionScheduler;
import io.contexa.contexacore.verification.evidence.DecisionPriorityCaptureSampling;
import io.contexa.contexacore.verification.evidence.VersionChangeCaptureSampling;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.io.IOException;
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
            "contexaSealedEvidencePromptTraceStore",
            "contexaSealedEvidencePromptCaptureAspect",
            "contexaSealedEvidenceLayer1CompletionAspect",
            "contexaSealedEvidencePackageAssembler",
            "contexaSealedEvidenceCaptureExecutor",
            "contexaSealedEvidenceCaptureHandler");

    private static final List<Class<?>> CAPTURE_TYPES = List.of(
            SealedEvidencePromptTraceStore.class,
            SealedEvidencePromptCaptureAspect.class,
            SealedEvidenceLayer1CompletionAspect.class,
            SealedEvidencePackageAssembler.class,
            SealedEvidenceCaptureHandler.class);

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    AopAutoConfiguration.class,
                    PqaSealedEvidenceAutoConfiguration.class,
                    SealedEvidenceAdvisorAutoConfiguration.class))
            .withBean("contexaObjectMapper", ObjectMapper.class, ObjectMapper::new)
            .withBean(CanonicalSecurityContextSerializer.class,
                    () -> new CanonicalSecurityContextSerializer(new ObjectMapper()))
            .withBean(SealedEvidencePackageIntegrity.class, SealedEvidencePackageIntegrity::new);

    @Test
    void ossWiresTheRealCaptureChainWithNamesThatDoNotCollideWithEnterprise() {
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    CAPTURE_TYPES.forEach(type -> assertThat(context).hasSingleBean(type));
                    assertThat(context).hasBean("contexaPqaOssSealedEvidenceCaptureExecutor");
                    assertThat(context).hasSingleBean(SealedEvidencePackageRetentionScheduler.class);
                    assertThat(context.getBean(SecurityEventHandler.class).getOrder()).isEqualTo(56);
                    List<String> ossNames = CAPTURE_TYPES.stream()
                            .flatMap(type -> Arrays.stream(context.getBeanNamesForType(type)))
                            .toList();
                    assertThat(ossNames).allMatch(name -> name.startsWith("contexaPqaOss"));
                    assertThat(ossNames).doesNotContainAnyElementsOf(ENTERPRISE_CAPTURE_BEAN_NAMES);
                    assertThat(context.containsBean("contexaSealedEvidenceCaptureExecutor")).isFalse();
                });
    }

    /**
     * Plan 3.4: the shadow runner is there whenever the sealed decisions are, without a setting, so a version the screen
     * runs alongside the decisions is run; without the decision's prompt template it reads no release and copies nothing.
     */
    @Test
    void theShadowRunnerIsThereWithoutASettingAndCopiesNothingWithoutATemplate() {
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(PromptShadowRunner.class);
                    SecurityEvent event = SecurityEvent.builder().eventId("evt-1").userId("user-1").build();
                    assertThat(context.getBean(PromptShadowRunner.class).prepare(event)).isNull();
                });
    }

    @Test
    void enterpriseEnabledCreatesNoOssCaptureOrRetentionBeans() {
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .withBean("contexaSealedEvidencePromptTraceStore", SealedEvidencePromptTraceStore.class,
                        SealedEvidencePromptTraceStore::new)
                .withPropertyValues("contexa.enterprise.enabled=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBeanNamesForType(SealedEvidencePromptTraceStore.class))
                            .containsExactly("contexaSealedEvidencePromptTraceStore");
                    assertThat(context).doesNotHaveBean(SealedEvidenceCaptureHandler.class);
                    assertThat(context).doesNotHaveBean(SealedEvidencePromptCaptureAspect.class);
                    assertThat(context).doesNotHaveBean(SealedEvidenceLayer1CompletionAspect.class);
                    assertThat(context).doesNotHaveBean(SealedEvidencePackageAssembler.class);
                    assertThat(context).doesNotHaveBean("contexaPqaOssSealedEvidenceCaptureExecutor");
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
                    assertThat(context).doesNotHaveBean("contexaPqaOssSealedEvidenceCaptureExecutor");
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

    /** R4-S4 (D-C): the retention period the host sets reaches the assembler; a period that is not positive fails fast. */
    @Test
    void theRetentionPeriodTheHostSetsReachesTheAssembler() {
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .withPropertyValues("contexa.pqa.oss.sealed-evidence.retention.period=30d")
                .run(context -> assertThat(ReflectionTestUtils.getField(
                        context.getBean(SealedEvidencePackageAssembler.class), "retention")).isEqualTo(Duration.ofDays(30)));
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .run(context -> assertThat(ReflectionTestUtils.getField(
                        context.getBean(SealedEvidencePackageAssembler.class), "retention")).isEqualTo(Duration.ofDays(90)));
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .withPropertyValues("contexa.pqa.oss.sealed-evidence.retention.period=0s")
                .run(context -> assertThat(context).hasFailed());
    }

    /**
     * R4-S6: the handler seals a stable share (1% by default) and every decision of the window after a change. Plan
     * 3.6: beside them the stopped and the risky allowed decisions, up to the daily limit (2000 packages by default).
     */
    @Test
    void theCaptureSampleTheHostSetsReachesTheHandler() {
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(SealedEvidenceCaptureSampling.class);
                    SealedEvidenceCaptureSampling sampling = context.getBean(SealedEvidenceCaptureSampling.class);
                    assertThat(sampling).isInstanceOf(DecisionPriorityCaptureSampling.class);
                    assertThat(ReflectionTestUtils.getField(sampling, "dailyLimit")).isEqualTo(2000)
                            .isEqualTo(DecisionPriorityCaptureSampling.DEFAULT_DAILY_LIMIT);
                    assertThat(ReflectionTestUtils.getField(sampling, "unknownFactThreshold")).isEqualTo(3)
                            .isEqualTo(DecisionPriorityCaptureSampling.DEFAULT_UNKNOWN_FACT_THRESHOLD);
                    Object windowAndShare = ReflectionTestUtils.getField(sampling, "base");
                    assertThat(windowAndShare).isInstanceOf(VersionChangeCaptureSampling.class);
                    assertThat(ReflectionTestUtils.getField(windowAndShare, "samplePercent")).isEqualTo(1);
                    assertThat(ReflectionTestUtils.getField(windowAndShare, "fullCaptureAfterChange")).isEqualTo(1000);
                    assertThat(ReflectionTestUtils.getField(context.getBean(SealedEvidenceCaptureHandler.class),
                            "sampling")).isSameAs(sampling);
                });
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .withPropertyValues("contexa.pqa.oss.sealed-evidence.sample-percent=100",
                        "contexa.pqa.oss.sealed-evidence.full-capture-after-change=0",
                        "contexa.pqa.oss.sealed-evidence.daily-limit=500",
                        "contexa.pqa.oss.sealed-evidence.unknown-fact-threshold=5")
                .run(context -> {
                    assertThat(context).hasSingleBean(SealedEvidenceCaptureSampling.class);
                    SealedEvidenceCaptureSampling sampling = context.getBean(SealedEvidenceCaptureSampling.class);
                    assertThat(ReflectionTestUtils.getField(sampling, "dailyLimit")).isEqualTo(500);
                    assertThat(ReflectionTestUtils.getField(sampling, "unknownFactThreshold")).isEqualTo(5);
                    Object windowAndShare = ReflectionTestUtils.getField(sampling, "base");
                    assertThat(ReflectionTestUtils.getField(windowAndShare, "samplePercent")).isEqualTo(100);
                    assertThat(ReflectionTestUtils.getField(windowAndShare, "fullCaptureAfterChange")).isEqualTo(0);
                });
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .withPropertyValues("contexa.pqa.oss.sealed-evidence.sample-percent=0")
                .run(context -> assertThat(context).hasFailed());
        // 0 is a setting: the window and the share alone. A negative limit and a threshold under 1 are refused.
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .withPropertyValues("contexa.pqa.oss.sealed-evidence.daily-limit=0")
                .run(context -> assertThat(context).hasNotFailed());
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .withPropertyValues("contexa.pqa.oss.sealed-evidence.daily-limit=-1")
                .run(context -> assertThat(context).hasFailed());
        runner.withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .withPropertyValues("contexa.pqa.oss.sealed-evidence.unknown-fact-threshold=0")
                .run(context -> assertThat(context).hasFailed());
    }

    /** The two settings of plan 3.6 are described for the host with the defaults the properties start from. */
    @Test
    void theDailyLimitAndTheUnknownFactThresholdAreDescribedWithTheirDefaults() throws IOException {
        JsonNode described = new ObjectMapper().readTree(new ClassPathResource(
                "META-INF/additional-spring-configuration-metadata.json").getInputStream()).path("properties");
        Map<String, JsonNode> byName = new HashMap<>();
        described.forEach(property -> byName.put(property.path("name").asText(), property));
        PqaOssSealedEvidenceCaptureProperties defaults = new PqaOssSealedEvidenceCaptureProperties();

        JsonNode dailyLimit = byName.get("contexa.pqa.oss.sealed-evidence.daily-limit");
        JsonNode unknownFacts = byName.get("contexa.pqa.oss.sealed-evidence.unknown-fact-threshold");
        assertThat(dailyLimit).isNotNull();
        assertThat(dailyLimit.path("defaultValue").asInt()).isEqualTo(defaults.getDailyLimit());
        assertThat(dailyLimit.path("description").asText()).contains("CHALLENGE", "UTC day", "sample-percent");
        assertThat(unknownFacts).isNotNull();
        assertThat(unknownFacts.path("defaultValue").asInt()).isEqualTo(defaults.getUnknownFactThreshold());
        assertThat(unknownFacts.path("description").asText()).isNotBlank();
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
