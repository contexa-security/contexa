package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.handler.handler.SealedEvidenceCaptureHandler;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.std.components.prompt.CorePromptEvidenceMetadataProvider;
import io.contexa.contexacore.verification.capture.PromptEvidenceMetadataProvider;
import io.contexa.contexacore.verification.capture.SealedEvidenceLayer1CompletionAspect;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptCaptureAspect;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageAssembler;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRetentionScheduler;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.time.Clock;
import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * OSS sealed evidence lifecycle for the prompt quality console.
 *
 * Runtime capture is the OSS wiring of the real decision pipeline: the prompt capture aspects record
 * the final LLM prompt, and SealedEvidenceCaptureHandler seals it together with the enforced decision
 * on the capture executor. Retention cleanup deletes packages whose expiresAt has passed.
 *
 * When Enterprise is enabled, Enterprise owns capture and retention (its schema keeps sealed packages
 * immutable), so none of these beans are created.
 */
@AutoConfiguration(after = PqaOfficialInspectionAutoConfiguration.class)
public class PqaSealedEvidenceAutoConfiguration {

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "false", matchIfMissing = true)
    @ConditionalOnProperty(prefix = "contexa.pqa.oss.sealed-evidence.retention", name = "enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnBean(SealedEvidencePackageRepository.class)
    static class OssSealedEvidenceRetentionConfiguration {

        @Bean(name = "pqaOssSealedEvidencePackageRetentionScheduler")
        @ConditionalOnMissingBean(SealedEvidencePackageRetentionScheduler.class)
        public SealedEvidencePackageRetentionScheduler pqaOssSealedEvidencePackageRetentionScheduler(
                SealedEvidencePackageRepository repository) {
            return new SealedEvidencePackageRetentionScheduler(repository);
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "contexa.enterprise", name = "enabled", havingValue = "false", matchIfMissing = true)
    @ConditionalOnProperty(prefix = "contexa.pqa.oss.sealed-evidence", name = "capture-enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnBean(SealedEvidencePackageRepository.class)
    @EnableConfigurationProperties(PqaOssSealedEvidenceCaptureProperties.class)
    static class OssSealedEvidenceCaptureConfiguration {

        static final String CAPTURE_EXECUTOR = "pqaOssSealedEvidenceCaptureExecutor";

        @Bean(name = CAPTURE_EXECUTOR)
        @ConditionalOnMissingBean(name = CAPTURE_EXECUTOR)
        public Executor pqaOssSealedEvidenceCaptureExecutor() {
            ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
            executor.setCorePoolSize(2);
            executor.setMaxPoolSize(4);
            executor.setQueueCapacity(512);
            executor.setThreadNamePrefix("oss-sealed-evidence-capture-");
            // Rejected captures are dropped by the handler; they must never run on the decision thread.
            executor.setRejectedExecutionHandler(new ThreadPoolExecutor.AbortPolicy());
            executor.setWaitForTasksToCompleteOnShutdown(true);
            executor.setAwaitTerminationSeconds(10);
            executor.initialize();
            return executor;
        }

        @Bean(name = "pqaOssPromptEvidenceMetadataProvider")
        @ConditionalOnMissingBean(PromptEvidenceMetadataProvider.class)
        public PromptEvidenceMetadataProvider pqaOssPromptEvidenceMetadataProvider() {
            return new CorePromptEvidenceMetadataProvider();
        }

        @Bean(name = "pqaOssSealedEvidencePromptTraceStore")
        @ConditionalOnMissingBean(SealedEvidencePromptTraceStore.class)
        public SealedEvidencePromptTraceStore pqaOssSealedEvidencePromptTraceStore(
                PromptEvidenceMetadataProvider promptEvidenceMetadataProvider,
                @Qualifier(CAPTURE_EXECUTOR) Executor captureExecutor,
                PqaOssSealedEvidenceCaptureProperties properties) {
            return new SealedEvidencePromptTraceStore(
                    promptEvidenceMetadataProvider,
                    captureExecutor,
                    properties.storeOptions(),
                    Clock.systemUTC());
        }

        @Bean(name = "pqaOssSealedEvidencePromptCaptureAspect")
        @ConditionalOnMissingBean(SealedEvidencePromptCaptureAspect.class)
        public SealedEvidencePromptCaptureAspect pqaOssSealedEvidencePromptCaptureAspect(
                SealedEvidencePromptTraceStore sealedEvidencePromptTraceStore) {
            return new SealedEvidencePromptCaptureAspect(sealedEvidencePromptTraceStore);
        }

        @Bean(name = "pqaOssSealedEvidenceLayer1CompletionAspect")
        @ConditionalOnMissingBean(SealedEvidenceLayer1CompletionAspect.class)
        public SealedEvidenceLayer1CompletionAspect pqaOssSealedEvidenceLayer1CompletionAspect(
                SealedEvidencePromptTraceStore sealedEvidencePromptTraceStore) {
            return new SealedEvidenceLayer1CompletionAspect(sealedEvidencePromptTraceStore);
        }

        @Bean(name = "pqaOssSealedEvidencePackageAssembler")
        @ConditionalOnMissingBean(SealedEvidencePackageAssembler.class)
        public SealedEvidencePackageAssembler pqaOssSealedEvidencePackageAssembler(
                ObjectMapper objectMapper,
                CanonicalSecurityContextSerializer canonicalSecurityContextSerializer,
                SealedEvidencePackageIntegrity sealedEvidencePackageIntegrity,
                SealedEvidencePromptTraceStore sealedEvidencePromptTraceStore) {
            return new SealedEvidencePackageAssembler(
                    objectMapper,
                    canonicalSecurityContextSerializer,
                    sealedEvidencePackageIntegrity,
                    sealedEvidencePromptTraceStore);
        }

        @Bean(name = "pqaOssSealedEvidenceCaptureHandler")
        @ConditionalOnMissingBean(SealedEvidenceCaptureHandler.class)
        public SealedEvidenceCaptureHandler pqaOssSealedEvidenceCaptureHandler(
                SealedEvidencePackageAssembler sealedEvidencePackageAssembler,
                SealedEvidencePackageRepository sealedEvidencePackageRepository,
                @Qualifier(CAPTURE_EXECUTOR) Executor captureExecutor,
                ObjectProvider<SecurityContextDataStore> securityContextDataStoreProvider) {
            return new SealedEvidenceCaptureHandler(
                    sealedEvidencePackageAssembler,
                    sealedEvidencePackageRepository,
                    captureExecutor,
                    securityContextDataStoreProvider.getIfAvailable());
        }
    }
}
