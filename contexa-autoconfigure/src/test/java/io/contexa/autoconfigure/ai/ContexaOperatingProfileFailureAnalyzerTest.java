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
package io.contexa.autoconfigure.ai;

import io.contexa.contexacommon.annotation.AiSecurityImportSelector;
import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.operating.ContexaOperatingProfileException;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexaidentity.security.core.context.OrderedSecurityFilterChain;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.core.Ordered;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.UnreachableFilterChainException;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * R-14 (F-2): with mode FULL Spring Security refuses an application chain that takes every request ahead of Contexa's main
 * chain before Contexa's start-up check runs, and the failure analysis tells that refusal in the check's words.
 */
class ContexaOperatingProfileFailureAnalyzerTest {

    private static final ContexaOperatingProfileException R14 =
            OwnershipStartupDiagnostics.applicationChainsRefused(List.of("hostChain"));

    @Test
    @DisplayName("R-14: FULL에서 Spring이 모든 요청 앱 체인을 거부하면, 실패 분석은 앱 체인 이름을 넣은 Contexa 거부 문구와 행동이다")
    void springsRefusalOfAnApplicationChainForEveryRequestIsToldInContexasWords() {
        FailureAnalysis analysis = new ContexaOperatingProfileFailureAnalyzer(active(SecurityMode.FULL))
                .analyze(asSpringThrowsIt(unreachable(applicationChain("hostChain"))));

        assertThat(analysis).isNotNull();
        assertThat(analysis.getDescription()).isEqualTo(R14.getMessage()).contains("[hostChain]");
        assertThat(analysis.getAction()).isEqualTo(R14.action());
        assertThat(analysis.getCause()).isInstanceOf(UnreachableFilterChainException.class);
    }

    @Test
    @DisplayName("빈이 아닌 모든 요청 앱 체인은 이름 대신 요청 범위로 알린다")
    void aChainThatIsNoBeanIsNamedByItsRequestMatcher() {
        FailureAnalysis analysis = new ContexaOperatingProfileFailureAnalyzer(active(SecurityMode.FULL))
                .analyze(unreachable(new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, List.of(mock(Filter.class)))));

        assertThat(analysis).isNotNull();
        assertThat(analysis.getDescription())
                .isEqualTo(OwnershipStartupDiagnostics.applicationChainsRefused(List.of(AnyRequestMatcher.INSTANCE.toString())).getMessage());
    }

    @Test
    @DisplayName("SANDBOX, Contexa가 켜지지 않은 앱, 환경이 없는 실패에서는 Spring의 거부를 그대로 둔다")
    void outsideModeFullSpringsWordsStand() {
        Throwable failure = asSpringThrowsIt(unreachable(applicationChain("hostChain")));

        assertThat(new ContexaOperatingProfileFailureAnalyzer(active(SecurityMode.SANDBOX)).analyze(failure)).isNull();
        StandardEnvironment inactive = new StandardEnvironment();
        inactive.getPropertySources().addFirst(new MapPropertySource("application",
                Map.of(ContexaOperatingProfile.PROP_MODE, SecurityMode.FULL.name())));
        assertThat(new ContexaOperatingProfileFailureAnalyzer(inactive).analyze(failure)).isNull();
        assertThat(new ContexaOperatingProfileFailureAnalyzer(null).analyze(failure)).isNull();
    }

    @Test
    @DisplayName("모든 요청을 받지 않는 체인끼리의 충돌(같은 범위 두 체인)은 R-14가 아니므로 Spring의 거부를 그대로 둔다")
    void aConflictOfNarrowedChainsIsNotR14() {
        DefaultSecurityFilterChain narrowed = new DefaultSecurityFilterChain(request -> true, List.of(mock(Filter.class)));

        assertThat(new ContexaOperatingProfileFailureAnalyzer(active(SecurityMode.FULL)).analyze(unreachable(narrowed))).isNull();
    }

    @Test
    @DisplayName("Contexa의 거부 예외는 모드와 환경에 상관없이 전처럼 그 이유와 행동으로 분석한다")
    void contexasOwnRefusalIsAnalysedAsBefore() {
        ContexaOperatingProfileException refused = new ContexaOperatingProfileException("the reason", "what to do");

        for (FailureAnalysis analysis : List.of(
                new ContexaOperatingProfileFailureAnalyzer(null).analyze(new BeanCreationException("bean", refused)),
                new ContexaOperatingProfileFailureAnalyzer(active(SecurityMode.SANDBOX)).analyze(refused))) {
            assertThat(analysis).isNotNull();
            assertThat(analysis.getDescription()).isEqualTo("the reason");
            assertThat(analysis.getAction()).isEqualTo("what to do");
            assertThat(analysis.getCause()).isSameAs(refused);
        }
    }

    /** The environment as @EnableAISecurity leaves it: its activation source, carrying the mode. */
    private static StandardEnvironment active(SecurityMode mode) {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource(AiSecurityImportSelector.ACTIVATION_SOURCE,
                Map.of(ContexaOperatingProfile.PROP_MODE, mode.name())));
        return environment;
    }

    /** An application chain for every request, named as Spring names a chain bean. */
    private static DefaultSecurityFilterChain applicationChain(String beanName) {
        DefaultSecurityFilterChain chain = new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, List.of(mock(Filter.class)));
        chain.setBeanName(beanName);
        return chain;
    }

    /** What Spring Security's validator throws: the chain for every request, then the chain behind it, Contexa's main one. */
    private static UnreachableFilterChainException unreachable(DefaultSecurityFilterChain everyRequest) {
        SecurityFilterChain contexa = new OrderedSecurityFilterChain(Ordered.LOWEST_PRECEDENCE, AnyRequestMatcher.INSTANCE, List.of());
        return new UnreachableFilterChainException("A filter chain that matches any request [" + everyRequest
                + "] has already been configured", everyRequest, contexa);
    }

    /** As the start reports it: inside the failure to create Spring Security's filter. */
    private static Throwable asSpringThrowsIt(UnreachableFilterChainException unreachable) {
        return new BeanCreationException("springSecurityFilterChain", "Failed to instantiate", unreachable);
    }
}
