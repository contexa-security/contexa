package io.contexa.demo.platform.configuration;

import io.contexa.contexacore.verification.capture.SealedEvidenceLayer1CompletionAspect;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptCaptureAspect;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptSnapshot;
import io.contexa.contexacore.verification.capture.SealedEvidencePromptTraceStore;
import io.contexa.contexacore.verification.capture.VerificationCaptureStoreOptions;
import io.contexa.demo.observation.prompt.service.GeneratedPromptRecorder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

@Configuration(proxyBeanMethods = false)
@Profile("contexa")
public class GeneratedPromptObservationConfiguration {

    @Bean
    SealedEvidencePromptTraceStore generatedPromptTraceStore() {
        return new SealedEvidencePromptTraceStore(null, Runnable::run,
                new VerificationCaptureStoreOptions(Duration.ofMinutes(5), 64, 64), Clock.systemUTC());
    }

    @Bean
    SealedEvidencePromptCaptureAspect generatedPromptCaptureAspect(SealedEvidencePromptTraceStore store) {
        return new SealedEvidencePromptCaptureAspect(store);
    }

    @Bean
    SealedEvidenceLayer1CompletionAspect generatedPromptCompletionAspect(SealedEvidencePromptTraceStore store,
            GeneratedPromptRecorder recorder) {
        return new SealedEvidenceLayer1CompletionAspect(event -> {
            store.complete(event);
            Object identity = event.getMetadata().get("eventProcessingIdentity");
            if (identity == null) {
                return;
            }
            SealedEvidencePromptSnapshot snapshot = store.find(identity.toString());
            if (snapshot != null && Objects.equals(event.getMetadata().get("eventProcessingOwnerToken"),
                    snapshot.securityEvent().getMetadata().get("eventProcessingOwnerToken"))) {
                recorder.record(snapshot);
            }
        });
    }
}
