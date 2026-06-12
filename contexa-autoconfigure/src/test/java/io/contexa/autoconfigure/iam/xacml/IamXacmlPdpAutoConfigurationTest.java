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
package io.contexa.autoconfigure.iam.xacml;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.AuthenticatedExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.AuthorityExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.url.WebSpelExpressionEvaluator;
import io.contexa.contexaiam.security.xacml.pdp.translator.*;
import io.contexa.contexaiam.security.xacml.pip.context.ContextHandler;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;

/**
 * Tests IamXacmlPdpAutoConfiguration bean registration.
 * Provides mock beans for dependencies that cause context startup failure.
 */
@DisplayName("IamXacmlPdpAutoConfiguration")
class IamXacmlPdpAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IamXacmlPdpAutoConfiguration.class))
            .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build())
            .withBean(RoleRepository.class, () -> mock(RoleRepository.class))
            .withBean(GroupRepository.class, () -> mock(GroupRepository.class))
            .withBean(PermissionRepository.class, () -> mock(PermissionRepository.class))
            .withBean(AuditLogRepository.class, () -> mock(AuditLogRepository.class))
            .withBean(ZeroTrustActionRepository.class, () -> mock(ZeroTrustActionRepository.class))
            .withBean(ContextHandler.class, () -> mock(ContextHandler.class))
            .withBean(RoleHierarchy.class,
                    () -> mock(RoleHierarchy.class));

    @Nested
    @DisplayName("SpEL function translator beans")
    class TranslatorBeans {

        @Test
        @DisplayName("Should register RoleFunctionTranslator")
        void shouldRegisterRoleTranslator() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(RoleFunctionTranslator.class);
            });
        }

        @Test
        @DisplayName("Should register AuthenticationFunctionTranslator")
        void shouldRegisterAuthTranslator() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(AuthenticationFunctionTranslator.class);
            });
        }

        @Test
        @DisplayName("Should register AuthorityFunctionTranslator")
        void shouldRegisterAuthorityTranslator() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(AuthorityFunctionTranslator.class);
            });
        }

        @Test
        @DisplayName("Should register IpAddressFunctionTranslator")
        void shouldRegisterIpTranslator() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(IpAddressFunctionTranslator.class);
            });
        }

        @Test
        @DisplayName("Should register DefaultFunctionTranslator")
        void shouldRegisterDefaultTranslator() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(DefaultFunctionTranslator.class);
            });
        }
    }

    @Nested
    @DisplayName("Expression evaluator beans")
    class EvaluatorBeans {

        @Test
        @DisplayName("Should register WebSpelExpressionEvaluator")
        void shouldRegisterWebSpelEvaluator() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(WebSpelExpressionEvaluator.class);
            });
        }

        @Test
        @DisplayName("Should register AuthenticatedExpressionEvaluator")
        void shouldRegisterAuthenticatedEvaluator() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(AuthenticatedExpressionEvaluator.class);
            });
        }

        @Test
        @DisplayName("Should register AuthorityExpressionEvaluator")
        void shouldRegisterAuthorityEvaluator() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(AuthorityExpressionEvaluator.class);
            });
        }
    }

    @Nested
    @DisplayName("PolicyTranslator bean")
    class PolicyTranslatorBean {

        @Test
        @DisplayName("Should register PolicyTranslator with all function translators")
        void shouldRegisterPolicyTranslator() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(PolicyTranslator.class);
            });
        }
    }

    @Nested
    @DisplayName("ConditionalOnMissingBean behavior")
    class ConditionalBehavior {

        @Test
        @DisplayName("Should not override existing RoleFunctionTranslator")
        void shouldNotOverrideExistingTranslator() {
            RoleFunctionTranslator custom = new RoleFunctionTranslator();
            contextRunner
                    .withBean(RoleFunctionTranslator.class, () -> custom)
                    .run(context -> {
                        assertThat(context).hasSingleBean(RoleFunctionTranslator.class);
                        assertThat(context.getBean(RoleFunctionTranslator.class)).isSameAs(custom);
                    });
        }
    }
}
