package io.contexa.showcase.workload.contexa.internal;

import io.contexa.autoconfigure.iam.admin.PqaOssSealedEvidenceCaptureProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.info.BuildProperties;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W7-13 (docs/showcase/화면설계-프롬프트신뢰-보강안.md 3.6): control D states how it seals the decision inputs, as bound:
 * the share of decisions it seals and how long a package whose latest inspection found nothing wrong is kept, in days;
 * nothing is stated without the OSS sealed evidence capture.
 */
class EngineInfoSealedEvidenceTest {

    @Test
    void theEngineStatesTheBoundCaptureShareAndCleanPeriod() {
        PqaOssSealedEvidenceCaptureProperties capture = new PqaOssSealedEvidenceCaptureProperties();
        capture.setSamplePercent(100);
        capture.getRetention().setCleanPeriod(Duration.ofDays(90));

        assertThat(engine(capture)).containsEntry("sealedEvidence",
                Map.of("samplePercent", 100, "cleanPeriodDays", 90));
    }

    @Test
    void withoutTheCaptureNothingIsStated() {
        assertThat(engine(null)).containsEntry("sealedEvidence", null);
    }

    private static Map<String, Object> engine(PqaOssSealedEvidenceCaptureProperties capture) {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("tiered", new TieredStrategyProperties());
        if (capture != null) {
            beans.addBean("capture", capture);
        }
        ContexaInternalController controller = new ContexaInternalController(null, null, null, null, null, null,
                null, null, null, null, beans.getBeanProvider(TieredStrategyProperties.class),
                new SecurityZeroTrustProperties(), "openai", "gpt-6-luna", "", "text-embedding-3-small", 1024,
                beans.getBeanProvider(BuildProperties.class), false, null,
                beans.getBeanProvider(PqaOssSealedEvidenceCaptureProperties.class));
        return controller.engine();
    }
}
