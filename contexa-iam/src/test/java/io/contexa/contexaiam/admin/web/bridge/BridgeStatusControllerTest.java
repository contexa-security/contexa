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
package io.contexa.contexaiam.admin.web.bridge;

import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.identity.IdentityDiagnostics;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.SubjectProblem;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@DisplayName("사용자 연동 상태 화면 컨트롤러")
class BridgeStatusControllerTest {

    private final Authentication admin = new UsernamePasswordAuthenticationToken("admin", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    private final Authentication user = new UsernamePasswordAuthenticationToken("alice", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_USER"));

    @Test
    @DisplayName("관리자는 진단 계수를 화면 값으로 받는다")
    void anAdministratorGetsTheCountsAsTheScreen() throws Exception {
        IdentityDiagnostics diagnostics = new IdentityDiagnostics();
        ContexaSubject subject = ContexaSubject.of("alice", "alice@example.com").build();
        diagnostics.record(ContexaIdentity.resolved(subject, ContexaIdentity.Source.SPRING_SECURITY, List.of(), null));
        diagnostics.record(ContexaIdentity.unresolved(ContexaIdentity.Outcome.FAILED, List.of(SubjectProblem.RESOLVER_FAILED)));
        diagnostics.problem(SubjectProblem.RESOLVER_FAILED, "a resolver of the test", new IllegalStateException("test"));

        MvcResult result = mvc(provider(diagnostics)).perform(get(BridgeStatusController.PATH).principal(admin))
                .andExpect(status().isOk())
                .andExpect(view().name("contexa/admin/zero-trust/bridge"))
                .andExpect(model().attribute("activePage", "zero-trust-bridge"))
                .andReturn();

        BridgeStatus bridge = (BridgeStatus) result.getModelAndView().getModel().get("bridge");
        assertThat(bridge.available()).isTrue();
        assertThat(bridge.checks()).isEqualTo(2);
        assertThat(bridge.failed()).isEqualTo(1);
        assertThat(bridge.attention()).isTrue();
        assertThat(bridge.problems()).extracting(BridgeStatus.Problem::kind).containsExactly(SubjectProblem.RESOLVER_FAILED);
        assertThat(bridge.sources()).extracting(BridgeStatus.Share::count).containsExactly(1L, 0L, 0L, 0L);
    }

    @Test
    @DisplayName("진단 빈이 없으면 꺼진 화면을 보인다")
    void withoutTheDiagnosticsBeanTheScreenSaysTheBridgeIsOff() throws Exception {
        MvcResult result = mvc(new StaticListableBeanFactory().getBeanProvider(IdentityDiagnostics.class))
                .perform(get(BridgeStatusController.PATH).principal(admin))
                .andExpect(status().isOk())
                .andExpect(view().name(BridgeStatusController.VIEW))
                .andExpect(model().attribute("activePage", BridgeStatusController.ACTIVE_PAGE))
                .andReturn();

        assertThat(result.getModelAndView().getModel().get("bridge")).isEqualTo(BridgeStatus.off());
    }

    @Test
    @DisplayName("관리자가 아니거나 로그인하지 않았으면 403이다")
    void someoneWhoIsNoAdministratorIsRefused() throws Exception {
        MockMvc mvc = mvc(provider(new IdentityDiagnostics()));

        mvc.perform(get(BridgeStatusController.PATH).principal(user)).andExpect(status().isForbidden());
        mvc.perform(get(BridgeStatusController.PATH)).andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("다른 콘솔 컨트롤러처럼 클래스 단위로 ROLE_ADMIN을 요구한다")
    void theClassAsksForTheAdministratorRole() {
        PreAuthorize guard = BridgeStatusController.class.getAnnotation(PreAuthorize.class);

        assertThat(guard).isNotNull();
        assertThat(guard.value()).isEqualTo("hasAuthority('ROLE_ADMIN')");
    }

    /** bridge v2 B5-3: the people whose copies are still kept in several rows, at most fifty, and whether there are more. */
    @Test
    @DisplayName("합치지 못한 사용자를 최대 50명 보이고 더 있으면 그렇다고 알린다")
    void thePeopleWhoseCopiesAreNotMergedAreShownUpToFifty() throws Exception {
        UserRepository users = mock(UserRepository.class);
        List<UserRepository.SplitCopies> rows = new ArrayList<>();
        for (int index = 0; index <= BridgeStatusController.SPLIT_COPIES_SHOWN; index++) {
            rows.add(split("kim" + index));
        }
        when(users.findSplitCopies(any())).thenReturn(rows);

        MvcResult result = MockMvcBuilders.standaloneSetup(new BridgeStatusController(provider(new IdentityDiagnostics()),
                        usersProvider(users))).build()
                .perform(get(BridgeStatusController.PATH).principal(admin))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, Object> shown = result.getModelAndView().getModel();
        assertThat((List<?>) shown.get("splitCopies")).hasSize(BridgeStatusController.SPLIT_COPIES_SHOWN);
        assertThat(shown.get("splitCopiesMore")).isEqualTo(true);
    }

    @Test
    @DisplayName("Contexa DB를 읽지 못해도 화면은 뜨고 합치지 못한 사용자는 비어 있다")
    void aDatabaseThatCannotBeReadLeavesTheListEmpty() throws Exception {
        UserRepository users = mock(UserRepository.class);
        when(users.findSplitCopies(any())).thenThrow(new IllegalStateException("database down"));

        MvcResult result = MockMvcBuilders.standaloneSetup(new BridgeStatusController(provider(new IdentityDiagnostics()),
                        usersProvider(users))).build()
                .perform(get(BridgeStatusController.PATH).principal(admin))
                .andExpect(status().isOk())
                .andReturn();

        assertThat((List<?>) result.getModelAndView().getModel().get("splitCopies")).isEmpty();
        assertThat(result.getModelAndView().getModel().get("splitCopiesMore")).isEqualTo(false);
    }

    private static UserRepository.SplitCopies split(String subject) {
        return new UserRepository.SplitCopies() {
            @Override
            public String getSubject() {
                return subject;
            }

            @Override
            public String getOrganization() {
                return null;
            }

            @Override
            public long getCopies() {
                return 2L;
            }
        };
    }

    private static ObjectProvider<UserRepository> usersProvider(UserRepository users) {
        return new StaticListableBeanFactory(Map.<String, Object>of("userRepository", users))
                .getBeanProvider(UserRepository.class);
    }

    private static ObjectProvider<IdentityDiagnostics> provider(IdentityDiagnostics diagnostics) {
        return new StaticListableBeanFactory(Map.<String, Object>of("contexaIdentityDiagnostics", diagnostics))
                .getBeanProvider(IdentityDiagnostics.class);
    }

    private static MockMvc mvc(ObjectProvider<IdentityDiagnostics> diagnostics) {
        return MockMvcBuilders.standaloneSetup(new BridgeStatusController(diagnostics)).build();
    }
}
