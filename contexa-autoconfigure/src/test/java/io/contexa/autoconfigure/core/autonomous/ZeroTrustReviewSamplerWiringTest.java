/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.core.autonomous;

import io.contexa.contexacore.autonomous.handler.handler.SealedEvidenceCaptureHandler;
import io.contexa.contexacore.monitoring.zerotrust.ZeroTrustReviewSampler;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.verification.evidence.DecisionPriorityCaptureSampling;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.function.BooleanSupplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Quality plan 3.6: the review sample takes the threshold of unknown facts the sealing of allowed decisions takes,
 * and draws only sealed decisions while the sealed evidence capture is a bean of the application.
 */
class ZeroTrustReviewSamplerWiringTest {

    @Test
    void theSampleTakesTheSealingsThresholdAndDrawsSealedDecisionsWhileTheCaptureIsThere() {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        MockEnvironment environment = new MockEnvironment()
                .withProperty("contexa.pqa.oss.sealed-evidence.unknown-fact-threshold", "5");
        CoreAutonomousEventAutoConfiguration configuration = new CoreAutonomousEventAutoConfiguration();

        ZeroTrustReviewSampler sampler = configuration.zeroTrustReviewSampler(beans.getBeanProvider(JdbcOperations.class),
                new SecurityZeroTrustProperties(), environment, beans.getBeanProvider(SealedEvidenceCaptureHandler.class));
        BooleanSupplier sealedOnly = (BooleanSupplier) ReflectionTestUtils.getField(sampler, "sealedOnly");

        assertThat(ReflectionTestUtils.getField(sampler, "unknownFactThreshold")).isEqualTo(5);
        assertThat(sealedOnly.getAsBoolean()).isFalse();
        beans.addBean("contexaPqaOssSealedEvidenceCaptureHandler", mock(SealedEvidenceCaptureHandler.class));
        assertThat(sealedOnly.getAsBoolean()).as("read when the sample is drawn").isTrue();

        ZeroTrustReviewSampler byDefault = configuration.zeroTrustReviewSampler(
                beans.getBeanProvider(JdbcOperations.class), new SecurityZeroTrustProperties(), new MockEnvironment(),
                beans.getBeanProvider(SealedEvidenceCaptureHandler.class));
        assertThat(ReflectionTestUtils.getField(byDefault, "unknownFactThreshold"))
                .isEqualTo(DecisionPriorityCaptureSampling.DEFAULT_UNKNOWN_FACT_THRESHOLD);
    }
}
