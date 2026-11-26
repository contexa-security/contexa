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
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.ai.ContexaSlotFilterRegistration;
import io.contexa.autoconfigure.ai.ContexaServletFilterOrder;
import io.contexa.contexacommon.operating.ConditionalOnMode;
import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.UrlPolicyEnforcementFilter;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.expression.SecurityExpressionHandler;

/**
 * Tests IamXacmlPepAutoConfiguration annotation structure and bean definitions.
 * Uses reflection instead of ApplicationContextRunner due to complex transitive dependencies.
 */
@DisplayName("IamXacmlPepAutoConfiguration")
class IamXacmlPepAutoConfigurationTest {

    @Nested
    @DisplayName("Class-level annotations")
    class ClassAnnotations {

        @Test
        @DisplayName("Should be annotated with @AutoConfiguration")
        void shouldBeAutoConfiguration() {
            assertThat(IamXacmlPepAutoConfiguration.class
                    .getAnnotation(AutoConfiguration.class)).isNotNull();
        }
    }

    @Nested
    @DisplayName("Bean method annotations")
    class BeanMethods {

        @Test
        @DisplayName("Should have expressionAuthorizationManagerResolver bean with @ConditionalOnMissingBean")
        void shouldHaveResolverBean() throws Exception {
            Method method = IamXacmlPepAutoConfiguration.class
                    .getDeclaredMethod("expressionAuthorizationManagerResolver",
                            List.class,
                            SecurityExpressionHandler.class);

            assertThat(method.getAnnotation(Bean.class)).isNotNull();
            assertThat(method.getAnnotation(ConditionalOnMissingBean.class)).isNotNull();
        }

        @Test
        @DisplayName("Should have customDynamicAuthorizationManager bean with @ConditionalOnMissingBean")
        void shouldHaveDynamicManagerBean() {
            boolean found = Arrays.stream(IamXacmlPepAutoConfiguration.class.getDeclaredMethods())
                    .filter(m -> m.getName().equals("customDynamicAuthorizationManager"))
                    .anyMatch(m -> m.getAnnotation(Bean.class) != null
                            && m.getAnnotation(ConditionalOnMissingBean.class) != null);

            assertThat(found).isTrue();
        }

        @Test
        @DisplayName("Should have protectableMethodAuthorizationManager bean with @ConditionalOnMissingBean")
        void shouldHaveProtectableManagerBean() {
            boolean found = Arrays.stream(IamXacmlPepAutoConfiguration.class.getDeclaredMethods())
                    .filter(m -> m.getName().equals("protectableMethodAuthorizationManager"))
                    .anyMatch(m -> m.getAnnotation(Bean.class) != null
                            && m.getAnnotation(ConditionalOnMissingBean.class) != null);

            assertThat(found).isTrue();
        }

        @Test
        @DisplayName("Should define exactly 6 bean methods (A1-8 added the delegator authority, R-7 the URL policy filter)")
        void shouldHaveSixBeanMethods() {
            long beanCount = Arrays.stream(IamXacmlPepAutoConfiguration.class.getDeclaredMethods())
                    .filter(m -> m.getAnnotation(Bean.class) != null)
                    .count();

            assertThat(beanCount).isEqualTo(6);
        }
    }

    /** R-7 of docs/agent/운영모드-정상화-구현계획.md: the URL policies on the application's requests. */
    @Nested
    @DisplayName("고객 경로의 URL 정책 필터(R-7)")
    class UrlPolicyEnforcement {

        @Test
        @DisplayName("운영 방식과 무관하게 모든 경로에서, Contexa 필터 슬롯 안에서 Contexa의 다른 집행 뒤에 돈다(R-10)")
        void runsInEveryWayOfRunningBehindTheChainAndContexasOtherEnforcement() throws Exception {
            Method bean = IamXacmlPepAutoConfiguration.class.getDeclaredMethod("urlPolicyEnforcementFilterRegistration",
                    CustomDynamicAuthorizationManager.class, ObjectMapper.class, ObjectProvider.class, ListableBeanFactory.class);
            DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();

            ContexaSlotFilterRegistration<UrlPolicyEnforcementFilter> registration = new IamXacmlPepAutoConfiguration()
                    .urlPolicyEnforcementFilterRegistration(mock(CustomDynamicAuthorizationManager.class), new ObjectMapper(),
                            beanFactory.getBeanProvider(SecurityProperties.class), beanFactory);

            assertThat(Arrays.asList(bean.getParameterTypes())).doesNotContain(BridgeProperties.class);
            assertThat(bean.getAnnotation(ConditionalOnMode.class)).isNull();
            assertThat(bean.getAnnotation(ConditionalOnOwnership.class)).isNull();
            assertThat(registration.runsInSlot()).isTrue();
            assertThat(registration.isEnabled()).as("the servlet container never maps it on its own").isFalse();
            assertThat(registration.getFilterName()).isEqualTo("contexaUrlPolicyEnforcementFilter");
            assertThat(registration.getUrlPatterns()).containsExactly("/*");
            assertThat(registration.getFilter()).isInstanceOf(UrlPolicyEnforcementFilter.class);
            assertThat(registration.getOrder())
                    .isEqualTo(SecurityProperties.DEFAULT_FILTER_ORDER + ContexaServletFilterOrder.URL_POLICY)
                    .isGreaterThan(SecurityProperties.DEFAULT_FILTER_ORDER + ContexaServletFilterOrder.USER_PATH_GUARD);
        }
    }
}
