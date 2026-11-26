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

import io.contexa.autoconfigure.iam.admin.IamAdminSessionTrackingConfiguration;
import io.contexa.autoconfigure.identity.SandboxStepUpAutoConfiguration;
import io.contexa.autoconfigure.identity.IdentitySecurityCoreAutoConfiguration;
import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexaiam.admin.web.auth.filter.SessionTrackingFilter;
import io.contexa.contexaiam.admin.web.auth.filter.TrackedSessionMarks;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import io.contexa.contexaidentity.security.zerotrust.SandboxUserPathGuard;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustAccessControlFilter;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustChallengeFilter;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * R-10 of docs/agent/운영모드-정상화-구현계획.md: the filters of Contexa's that act on what the Spring Security filter chain
 * established are the members of Contexa's one filter slot, right after that chain, in a fixed order. The servlet
 * container never maps one of them on its own, so no filter of the application's runs between two of them.
 */
@DisplayName("보안 체인 뒤 Contexa 필터는 모두 한 슬롯의 구성원이다(R-10)")
class ContexaServletFilterOrderTest {

    private static final int CHAIN = SecurityProperties.DEFAULT_FILTER_ORDER;

    private final Filter filter = mock(Filter.class);

    @Test
    @DisplayName("구성원은 컨테이너에 따로 매핑되지 않고, 보안 체인 순서 + 자리 값으로 슬롯 안 순서를 정한다")
    void aMemberIsNeverMappedOnItsOwnAndTakesItsPlaceInTheSlot() {
        ContexaSlotFilterRegistration<Filter> member = ContexaServletFilterOrder.member(filter, "contexaProbe", CHAIN,
                ContexaServletFilterOrder.ACCESS_CONTROL);

        assertThat(member.isEnabled()).as("the servlet container never maps a member on its own").isFalse();
        assertThat(member.runsInSlot()).isTrue();
        assertThat(member.getFilterName()).isEqualTo("contexaProbe");
        assertThat(member.getOrder()).isEqualTo(CHAIN + ContexaServletFilterOrder.ACCESS_CONTROL);
        assertThat(member.getUrlPatterns()).containsExactly("/*");
    }

    @Test
    @DisplayName("Spring Boot의 등록 끄기(setEnabled(false))는 그 필터를 슬롯에서 뺀다")
    void switchingAMemberOffTakesItOutOfTheSlot() {
        ContexaSlotFilterRegistration<Filter> member = ContexaServletFilterOrder.member(filter, "contexaProbe", CHAIN,
                ContexaServletFilterOrder.CHALLENGE);

        member.setEnabled(false);

        assertThat(member.runsInSlot()).isFalse();
        assertThat(member.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("앱이 보안 체인 순서를 옮겨도 슬롯과 구성원은 그 바로 뒤에 선다")
    void followsAMovedSecurityChain() {
        ContexaSlotFilterRegistration<Filter> member = ContexaServletFilterOrder.member(filter, "contexaProbe", 10,
                ContexaServletFilterOrder.ACCESS_CONTROL);

        assertThat(member.getOrder()).isEqualTo(13);
    }

    @Test
    @DisplayName("슬롯 안 순서: bridge, CHALLENGE, BLOCK·ESCALATE, 사용자 경로 가드, URL 정책, 세션 추적")
    void theOrderInsideTheSlotIsFixed() {
        assertThat(new int[]{ContexaServletFilterOrder.BRIDGE, ContexaServletFilterOrder.CHALLENGE,
                ContexaServletFilterOrder.ACCESS_CONTROL, ContexaServletFilterOrder.USER_PATH_GUARD,
                ContexaServletFilterOrder.URL_POLICY, ContexaServletFilterOrder.SESSION_TRACKING}).isSorted();
        assertThat(ContexaServletFilterOrder.ADDRESS_CONTROL).as("the address control stays ahead of the chain").isNegative();
    }

    @Test
    @DisplayName("bridge는 모드를 따지지 않고 슬롯의 첫 구성원이다")
    void theBridgeIsTheFirstMemberInEveryMode() {
        ContexaSlotFilterRegistration<BridgeResolutionFilter> bridge = new AiBridgeConfiguration()
                .bridgeResolutionFilterRegistration(mock(BridgeResolutionFilter.class), noSecurityProperties());

        assertThat(bridge.runsInSlot()).isTrue();
        assertThat(bridge.isEnabled()).isFalse();
        assertThat(bridge.getFilterName()).isEqualTo("contexaBridgeResolutionFilter");
        assertThat(bridge.getOrder()).isEqualTo(CHAIN + ContexaServletFilterOrder.BRIDGE);
        assertThat(bridge.getUrlPatterns()).containsExactly("/*");
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({"SANDBOX, true", "FULL, false"})
    @DisplayName("Zero Trust 집행 필터는 SANDBOX에서 슬롯에서 돌고, FULL에서는 Contexa 체인 안에서만 돈다")
    void theZeroTrustFiltersRunInTheSlotUnderSandboxOnly(String mode, boolean inSlot) {
        ObjectProvider<BridgeProperties> bridgeProperties = bridgeProperties(mode);
        IdentitySecurityCoreAutoConfiguration configuration = new IdentitySecurityCoreAutoConfiguration();

        ContexaSlotFilterRegistration<ZeroTrustChallengeFilter> challenge = configuration.zeroTrustChallengeFilterRegistrationBean(
                mock(ZeroTrustChallengeFilter.class), bridgeProperties, noSecurityProperties());
        ContexaSlotFilterRegistration<ZeroTrustAccessControlFilter> access = configuration.zeroTrustAccessControlFilterRegistrationBean(
                mock(ZeroTrustAccessControlFilter.class), bridgeProperties, noSecurityProperties());

        assertThat(challenge.runsInSlot()).isEqualTo(inSlot);
        assertThat(access.runsInSlot()).isEqualTo(inSlot);
        assertThat(challenge.isEnabled()).isFalse();
        assertThat(access.isEnabled()).isFalse();
        assertThat(challenge.getFilterName()).isEqualTo("contexaZeroTrustChallengeFilter");
        assertThat(access.getFilterName()).isEqualTo("contexaZeroTrustAccessControlFilter");
        assertThat(challenge.getOrder()).isEqualTo(CHAIN + ContexaServletFilterOrder.CHALLENGE);
        assertThat(access.getOrder()).isEqualTo(CHAIN + ContexaServletFilterOrder.ACCESS_CONTROL);
    }

    @Test
    @DisplayName("사용자 경로 가드는 자기 경로만 받는 슬롯 구성원이다")
    void theUserPathGuardIsAMemberOnItsOwnPaths() {
        ContexaSlotFilterRegistration<SandboxUserPathGuard> guard = new SandboxStepUpAutoConfiguration()
                .sandboxUserPathGuardRegistration(noSecurityProperties());

        assertThat(guard.runsInSlot()).isTrue();
        assertThat(guard.isEnabled()).isFalse();
        assertThat(guard.getFilterName()).isEqualTo("contexaSandboxUserPathGuard");
        assertThat(guard.getUrlPatterns()).containsExactlyElementsOf(SandboxUserPathGuard.URL_PATTERNS);
        assertThat(guard.getOrder()).isEqualTo(CHAIN + ContexaServletFilterOrder.USER_PATH_GUARD);
    }

    @Test
    @DisplayName("세션 추적은 슬롯의 마지막 구성원이다")
    void theSessionTrackingIsTheLastMember() {
        ContexaSlotFilterRegistration<SessionTrackingFilter> tracking = new IamAdminSessionTrackingConfiguration()
                .sessionTrackingFilter(mock(SessionManagementService.class), mock(ActiveSessionRepository.class),
                        new TrackedSessionMarks(), noSecurityProperties());

        assertThat(tracking.runsInSlot()).isTrue();
        assertThat(tracking.isEnabled()).isFalse();
        assertThat(tracking.getFilterName()).isEqualTo("contexaSessionTrackingFilter");
        assertThat(tracking.getUrlPatterns()).containsExactly("/*");
        assertThat(tracking.getOrder()).isEqualTo(CHAIN + ContexaServletFilterOrder.SESSION_TRACKING);
    }

    private static ObjectProvider<SecurityProperties> noSecurityProperties() {
        return new DefaultListableBeanFactory().getBeanProvider(SecurityProperties.class);
    }

    private static ObjectProvider<BridgeProperties> bridgeProperties(String mode) {
        BridgeProperties properties = new BridgeProperties();
        properties.setEnvironment(new MockEnvironment().withProperty(ContexaOperatingProfile.PROP_MODE, mode));
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerSingleton("bridgeProperties", properties);
        return beanFactory.getBeanProvider(BridgeProperties.class);
    }
}
