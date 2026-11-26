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

import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.identity.IdentityDiagnostics;
import io.contexa.contexacommon.security.bridge.identity.IdentityResolution;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubjectMapper;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubjectResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * bridge v2 step B3: the identity resolution is made from what the application declared, each of a resolver and a mapper
 * at most once, and a start that cannot tell which one names the user stops with what to do.
 */
@DisplayName("레거시 연동 표준 v2: 신원 해석 빈은 앱의 선언에서 만들어진다")
class AiBridgeIdentityResolutionTest {

    private static final ContexaSubjectResolver KIM = view -> Optional.of(ContexaSubject.of("kim01", "kim01@seum.example").build());

    @Test
    @DisplayName("앱이 아무것도 선언하지 않으면 리졸버 없이 만들어지고 기본 출처 순서를 쓴다")
    void nothingDeclared() {
        IdentityResolution resolution = resolution(new BridgeProperties(), new DefaultListableBeanFactory());

        assertThat(resolution.hasResolver()).isFalse();
        assertThat(resolution.settings().order()).containsExactly(ContexaIdentity.Source.SPRING_SECURITY,
                ContexaIdentity.Source.RESOLVER, ContexaIdentity.Source.REQUEST_ATTRIBUTE);
    }

    @Test
    @DisplayName("앱의 리졸버 빈 하나를 쓴다")
    void theApplicationsResolverIsUsed() {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton("legacyLoginResolver", KIM);

        IdentityResolution resolution = resolution(new BridgeProperties(), beans);

        assertThat(resolution.hasResolver()).isTrue();
        assertThat(resolution.resolve(new MockHttpServletRequest(), null).getUserId()).isEqualTo("kim01");
    }

    @Test
    @DisplayName("리졸버 빈이 둘이면 어느 것이 사용자를 이름 짓는지 알 수 없으므로 두 이름을 밝히고 기동을 멈춘다")
    void twoResolversStopTheStart() {
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton("sessionResolver", KIM);
        beans.registerSingleton("tokenResolver", KIM);

        assertThatThrownBy(() -> resolution(new BridgeProperties(), beans))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ContexaSubjectResolver")
                .hasMessageContaining("sessionResolver")
                .hasMessageContaining("tokenResolver");
    }

    @Test
    @DisplayName("매퍼 빈이 둘이어도 기동을 멈춘다")
    void twoMappersStopTheStart() {
        ContexaSubjectMapper mapper = authentication -> Optional.empty();
        DefaultListableBeanFactory beans = new DefaultListableBeanFactory();
        beans.registerSingleton("firstMapper", mapper);
        beans.registerSingleton("secondMapper", mapper);

        assertThatThrownBy(() -> resolution(new BridgeProperties(), beans))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ContexaSubjectMapper");
    }

    @Test
    @DisplayName("알 수 없는 출처를 설정하면 기동을 멈추고 쓸 수 있는 이름을 알린다")
    void anUnknownSourceStopsTheStart() {
        BridgeProperties properties = new BridgeProperties();
        properties.setIdentitySources(List.of("session"));

        assertThatThrownBy(() -> resolution(properties, new DefaultListableBeanFactory()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring-security, resolver and request-attribute");
    }

    private static IdentityResolution resolution(BridgeProperties properties, DefaultListableBeanFactory beans) {
        return new AiBridgeConfiguration().identityResolution(properties, beans, new IdentityDiagnostics());
    }
}
