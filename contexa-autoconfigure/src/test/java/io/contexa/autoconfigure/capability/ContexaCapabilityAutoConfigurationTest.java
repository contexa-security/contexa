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
package io.contexa.autoconfigure.capability;

import io.contexa.contexacommon.autoconfigure.capability.CapabilityStatus;
import io.contexa.contexacommon.autoconfigure.capability.CapabilityRequirement;
import io.contexa.contexacommon.autoconfigure.capability.ContexaCapability;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@ExtendWith(OutputCaptureExtension.class)
class ContexaCapabilityAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ContexaCapabilityAutoConfiguration.class));

    @Test
    @DisplayName("defaults to AUTO mode without verbose application properties")
    void defaultsToAutoMode() {
        contextRunner.run(context -> {
            ContexaCapabilityProperties properties = context.getBean(ContexaCapabilityProperties.class);

            assertThat(properties.getMode().name()).isEqualTo("AUTO");
            assertThat(properties.getRequired()).isEmpty();
        });
    }

    @Test
    @DisplayName("PQA capability stays inactive when enterprise features are disabled")
    void pqaCapabilityStaysInactiveWhenEnterpriseIsDisabled() {
        contextRunner
                .withPropertyValues(
                        "spring.application.name=contexa-demo",
                        "contexa.enterprise.enabled=false",
                        "contexa.capability.mode=off")
                .run(context -> {
                    CapabilityRequirementResolver resolver = context.getBean(CapabilityRequirementResolver.class);
                    CapabilityRequirement requirement = resolver.requirement(ContexaCapability.PQA_ENGINE);

                    assertThat(requirement.enabled()).isFalse();
                    assertThat(requirement.required()).isFalse();
                });
    }

    @Test
    @DisplayName("detects incomplete RAG vector chain when VectorStore exists but UnifiedVectorService is missing")
    void detectsIncompleteRagVectorChain() {
        contextRunner
                .withBean(VectorStore.class, () -> mock(VectorStore.class))
                .withPropertyValues(
                        "contexa.capability.mode=warn",
                        "contexa.capability.required.rag-vector=true")
                .run(context -> {
                    ContexaCapabilityRegistry registry = context.getBean(ContexaCapabilityRegistry.class);

                    assertThat(registry.lastResults())
                            .filteredOn(result -> result.capability() == ContexaCapability.RAG_VECTOR)
                            .singleElement()
                            .satisfies(result -> {
                                assertThat(result.status()).isEqualTo(CapabilityStatus.INACTIVE_UNEXPECTED);
                                assertThat(result.required()).isTrue();
                                assertThat(result.presentBeans()).contains("org.springframework.ai.vectorstore.VectorStore");
                                assertThat(result.missingBeans()).contains(
                                        "io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer",
                                        "io.contexa.contexacore.std.rag.service.UnifiedVectorService");
                            });
                });
    }

    @Test
    @DisplayName("fails fast when a required capability is incomplete")
    void failsFastWhenRequiredCapabilityIsIncomplete() {
        contextRunner
                .withBean(VectorStore.class, () -> mock(VectorStore.class))
                .withPropertyValues(
                        "contexa.capability.mode=fail-fast",
                        "contexa.capability.required.rag-vector=true")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    @DisplayName("fail-fast message and console logs include actionable guidance")
    void failFastMessageAndConsoleLogsIncludeActionableGuidance(CapturedOutput output) {
        contextRunner
                .withPropertyValues(
                        "spring.application.name=contexa-demo",
                        "contexa.capability.mode=fail-fast",
                        "contexa.capability.required.llm-runtime=false",
                        "contexa.capability.required.embedding-runtime=false",
                        "contexa.autonomous.enabled=false",
                        "contexa.capability.required.rag-vector=true")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasMessageContaining("rag-vector")
                            .hasMessageContaining("spring-ai-starter-vector-store-pgvector")
                            .hasMessageContaining("Verify datasource connectivity");
                    assertThat(output.getOut())
                            .contains("[ContexaCapability] rag-vector")
                            .contains("Recommended actions")
                            .contains("spring-ai-starter-vector-store-pgvector")
                            .contains("Verify datasource connectivity");
                });
    }

    @Test
    @DisplayName("AUTO mode fails fast for Contexa-owned applications without verbose required properties")
    void autoModeFailsFastForContexaOwnedApplication() {
        contextRunner
                .withBean(VectorStore.class, () -> mock(VectorStore.class))
                .withPropertyValues("spring.application.name=contexa-site")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    @DisplayName("customer applications suppress internal-only warnings by default")
    void suppressesInternalOnlyWarningsForCustomerApplications(CapturedOutput output) {
        contextRunner
                .withBean(VectorStore.class, () -> mock(VectorStore.class))
                .withPropertyValues(
                        "spring.application.name=legacy-customer-app",
                        "contexa.capability.mode=warn",
                        "contexa.capability.required.rag-vector=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(output.getOut()).doesNotContain("[ContexaCapability] rag-vector");
                });
    }

    @Test
    @DisplayName("customer applications still see actionable capability warnings")
    void keepsActionableWarningsForCustomerApplications(CapturedOutput output) {
        contextRunner
                .withPropertyValues(
                        "spring.application.name=legacy-customer-app",
                        "contexa.capability.mode=warn",
                        "contexa.capability.required.rag-vector=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(output.getOut()).contains("[ContexaCapability] rag-vector");
                    assertThat(output.getOut()).contains("org.springframework.ai.vectorstore.VectorStore");
                    assertThat(output.getOut()).contains("spring-ai-starter-vector-store-pgvector");
                    assertThat(output.getOut()).doesNotContain("io.contexa.contexacore.std.rag.service.UnifiedVectorService");
                });
    }

    @Test
    @DisplayName("customer diagnostics endpoint hides internal-only capability defects")
    void customerDiagnosticsHideInternalOnlyCapabilityDefects() {
        contextRunner
                .withBean(VectorStore.class, () -> mock(VectorStore.class))
                .withPropertyValues(
                        "spring.application.name=legacy-customer-app",
                        "contexa.capability.mode=warn",
                        "contexa.capability.required.rag-vector=true")
                .run(context -> {
                    CapabilityDiagnosticsEndpoint endpoint = context.getBean(CapabilityDiagnosticsEndpoint.class);

                    assertThat(endpoint.diagnostics().capabilities())
                            .filteredOn(result -> result.capability() == ContexaCapability.RAG_VECTOR)
                            .isEmpty();
                });
    }

    @Test
    @DisplayName("Contexa-owned diagnostics endpoint keeps full internal defect detail")
    void contexaOwnedDiagnosticsKeepFullInternalDefectDetail() {
        contextRunner
                .withBean(VectorStore.class, () -> mock(VectorStore.class))
                .withPropertyValues(
                        "spring.application.name=contexa-site",
                        "contexa.capability.mode=warn",
                        "contexa.capability.required.rag-vector=true")
                .run(context -> {
                    CapabilityDiagnosticsEndpoint endpoint = context.getBean(CapabilityDiagnosticsEndpoint.class);

                    assertThat(endpoint.diagnostics().capabilities())
                            .filteredOn(result -> result.capability() == ContexaCapability.RAG_VECTOR)
                            .singleElement()
                            .satisfies(result -> assertThat(result.missingBeans())
                                    .contains("io.contexa.contexacore.std.rag.service.UnifiedVectorService"));
                });
    }

    @Test
    @DisplayName("diagnostics endpoint backs off when Actuator is not on the classpath")
    void diagnosticsEndpointBacksOffWithoutActuator() {
        contextRunner
                .withClassLoader(new FilteredClassLoader("org.springframework.boot.actuate"))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean("capabilityDiagnosticsEndpoint");
                });
    }
}
