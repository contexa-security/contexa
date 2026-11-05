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
package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacommon.security.MfaPendingSession;
import io.contexa.contexacommon.security.UserPasswordChangedEvent;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRedisRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IForceLogoutService;
import io.contexa.contexacore.autonomous.service.UserAccountChangeListener;
import io.contexa.contexacore.autonomous.store.RedisSecurityContextDataStore;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.security.zerotrust.RedisZeroTrustSecurityService;
import io.contexa.contexaiam.admin.web.auth.service.PasswordChangeService;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.context.MessageSource;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("PasswordChangeController")
class PasswordChangeControllerTest {

    @Mock
    private PasswordChangeService passwordChangeService;

    @Mock
    private PasswordPolicyService passwordPolicyService;

    @Mock
    private MessageSource messageSource;

    private PasswordChangeController controller;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        controller = new PasswordChangeController(passwordChangeService, passwordPolicyService, messageSource);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    /** PR-69: the address throttle of the password change is no better than the address it is given. */
    @Test
    @DisplayName("a forged forwarded header does not change the address of a password change")
    void aForgedHeaderDoesNotChangeTheAddress() throws Exception {
        mockMvc.perform(post("/contexa/password-change")
                        .param("username", "admin")
                        .param("currentPassword", "current")
                        .param("newPassword", "New-Pass-1")
                        .param("confirmPassword", "New-Pass-1")
                        .header("X-Forwarded-For", "198.51.100.77")
                        .with(request -> {
                            request.setRemoteAddr("203.0.113.7");
                            return request;
                        }))
                .andExpect(status().is3xxRedirection());

        verify(passwordChangeService).changePassword("admin", "current", "New-Pass-1", "New-Pass-1", "203.0.113.7");
    }

    @Nested
    @DisplayName("showPasswordChangeForm")
    class ShowForm {

        @Test
        @DisplayName("should render password change form with username and policy")
        void success() throws Exception {
            PasswordPolicy policy = new PasswordPolicy();
            when(passwordPolicyService.getCurrentPolicy()).thenReturn(policy);

            mockMvc.perform(get("/contexa/password-change")
                            .param("username", "testuser"))
                    .andExpect(status().isOk())
                    .andExpect(view().name("contexa/password-change"))
                    .andExpect(model().attribute("username", "testuser"))
                    .andExpect(model().attribute("policy", policy));
        }
    }

    @Nested
    @DisplayName("processPasswordChange")
    class ProcessChange {

        @Test
        @DisplayName("a name with characters of its own stays one parameter of the address it is sent back to")
        void nameInTheAddressIsEncoded() throws Exception {
            doThrow(new PasswordChangeService.PasswordChangeException("msg.password.change.current.incorrect"))
                    .when(passwordChangeService)
                    .changePassword("a b&admin=1", "wrong", "newpass", "newpass", "127.0.0.1");

            mockMvc.perform(post("/contexa/password-change")
                            .param("username", "a b&admin=1")
                            .param("currentPassword", "wrong")
                            .param("newPassword", "newpass")
                            .param("confirmPassword", "newpass"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/password-change?username=a+b%26admin%3D1"));
        }

        @Test
        @DisplayName("should redirect with error when user does not exist")
        void userNotFound() throws Exception {
            doThrow(new PasswordChangeService.PasswordChangeException("msg.password.change.user.not.found"))
                    .when(passwordChangeService)
                    .changePassword("none", "pass", "newpass", "newpass", "127.0.0.1");

            mockMvc.perform(post("/contexa/password-change")
                            .param("username", "none")
                            .param("currentPassword", "pass")
                            .param("newPassword", "newpass")
                            .param("confirmPassword", "newpass"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/password-change?username=none"))
                    .andExpect(flash().attribute("errorMessage", "msg.password.change.user.not.found"));
        }

        @Test
        @DisplayName("should redirect with error when current password does not match")
        void incorrectCurrentPassword() throws Exception {
            doThrow(new PasswordChangeService.PasswordChangeException("msg.password.change.current.incorrect"))
                    .when(passwordChangeService)
                    .changePassword("testuser", "wrong", "newpass", "newpass", "127.0.0.1");

            mockMvc.perform(post("/contexa/password-change")
                            .param("username", "testuser")
                            .param("currentPassword", "wrong")
                            .param("newPassword", "newpass")
                            .param("confirmPassword", "newpass"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/password-change?username=testuser"))
                    .andExpect(flash().attribute("errorMessage", "msg.password.change.current.incorrect"));
        }

        @Test
        @DisplayName("should redirect with error when new passwords do not match")
        void newPasswordMismatch() throws Exception {
            doThrow(new PasswordChangeService.PasswordChangeException("msg.password.change.mismatch"))
                    .when(passwordChangeService)
                    .changePassword("testuser", "correct", "newpass", "diffpass", "127.0.0.1");

            mockMvc.perform(post("/contexa/password-change")
                            .param("username", "testuser")
                            .param("currentPassword", "correct")
                            .param("newPassword", "newpass")
                            .param("confirmPassword", "diffpass"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/password-change?username=testuser"))
                    .andExpect(flash().attribute("errorMessage", "msg.password.change.mismatch"));
        }

        @Test
        @DisplayName("should redirect with error when new password violates policy")
        void policyViolation() throws Exception {
            doThrow(new PasswordChangeService.PasswordChangeException("msg.password.change.policy.violation", "Too short"))
                    .when(passwordChangeService)
                    .changePassword("testuser", "correct", "weak", "weak", "127.0.0.1");

            mockMvc.perform(post("/contexa/password-change")
                            .param("username", "testuser")
                            .param("currentPassword", "correct")
                            .param("newPassword", "weak")
                            .param("confirmPassword", "weak"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/password-change?username=testuser"))
                    .andExpect(flash().attribute("errorMessage", "msg.password.change.policy.violation"));
        }

        @Test
        @DisplayName("should redirect with error when password is reused")
        void passwordReused() throws Exception {
            doThrow(new PasswordChangeService.PasswordChangeException("msg.password.change.reused"))
                    .when(passwordChangeService)
                    .changePassword("testuser", "correct", "validpass", "validpass", "127.0.0.1");

            mockMvc.perform(post("/contexa/password-change")
                            .param("username", "testuser")
                            .param("currentPassword", "correct")
                            .param("newPassword", "validpass")
                            .param("confirmPassword", "validpass"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/password-change?username=testuser"))
                    .andExpect(flash().attribute("errorMessage", "msg.password.change.reused"));
        }

        @Test
        @DisplayName("should change password and redirect to login on success")
        void success() throws Exception {
            mockMvc.perform(post("/contexa/password-change")
                            .param("username", "testuser")
                            .param("currentPassword", "correct")
                            .param("newPassword", "validpass")
                            .param("confirmPassword", "validpass"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/contexa/admin/login"))
                    .andExpect(flash().attribute("message", "msg.password.change.success"));

            verify(passwordChangeService).changePassword("testuser", "correct", "validpass", "validpass", "127.0.0.1");
        }    }

    /**
     * What a refused request sees, with the service as it runs: the right password of an account that may not change here
     * reads as a wrong one, so whoever holds a password learns nothing of the state of the account.
     */
    @Nested
    @DisplayName("every refusal answers as a wrong password")
    class OneAnswer {

        private final UserRepository users = mock(UserRepository.class);
        private final PasswordEncoder encoder = mock(PasswordEncoder.class);
        private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
        private final Users account = Users.builder().username("alice").password("{hash}old").build();
        private final ObjectProvider<ZeroTrustActionRepository> decisions = mock(ObjectProvider.class);
        private SecurityContextDataStore dataStore = mock(SecurityContextDataStore.class);
        private IForceLogoutService logout = mock(IForceLogoutService.class);
        private MockMvc answering;

        @BeforeEach
        void realService() {
            when(users.findByUsername("alice")).thenReturn(Optional.of(account));
            when(encoder.matches("right", "{hash}old")).thenReturn(true);
            when(encoder.encode(anyString())).thenReturn("{hash}decoy");
            ObjectProvider<LoginPolicyHandler> noPolicy = mock(ObjectProvider.class);
            when(decisions.getIfAvailable()).thenReturn(actions);
            PasswordChangeService service = new PasswordChangeService(users, encoder, passwordPolicyService, noPolicy,
                    decisions, () -> true, this::tell);
            answering = MockMvcBuilders.standaloneSetup(
                    new PasswordChangeController(service, passwordPolicyService, messageSource)).build();
        }

        /** The listener of the application, without a transaction around it: what it does happens inside the request. */
        private void tell(Object event) {
            StaticListableBeanFactory beans = new StaticListableBeanFactory();
            beans.addBean("store", dataStore);
            beans.addBean("forceLogout", logout);
            new UserAccountChangeListener(beans.getBeanProvider(SecurityContextDataStore.class),
                    beans.getBeanProvider(IForceLogoutService.class)).onPasswordChanged((UserPasswordChangedEvent) event);
        }

        @AfterEach
        void signOut() {
            SecurityContextHolder.clearContext();
        }

        private MvcResult post(String currentPassword) throws Exception {
            return post(currentPassword, new MockHttpSession());
        }

        private MvcResult post(String currentPassword, MockHttpSession session) throws Exception {
            return answering.perform(MockMvcRequestBuilders.post("/contexa/password-change")
                            .session(session)
                            .param("username", "alice")
                            .param("currentPassword", currentPassword)
                            .param("newPassword", "New-Pass-1")
                            .param("confirmPassword", "New-Pass-1"))
                    .andReturn();
        }

        private void assertAnswersAsWrong(MvcResult refused) throws Exception {
            MvcResult wrong = post("wrong");
            assertThat(refused.getResponse().getStatus()).isEqualTo(wrong.getResponse().getStatus()).isEqualTo(302);
            assertThat(refused.getResponse().getRedirectedUrl()).isEqualTo(wrong.getResponse().getRedirectedUrl())
                    .isEqualTo("/contexa/password-change?username=alice");
            Map<String, Object> flash = refused.getFlashMap();
            assertThat(flash).isEqualTo(wrong.getFlashMap())
                    .containsEntry("errorMessage", "msg.password.change.current.incorrect");
            assertThat(refused.getResponse().getContentAsString()).isEqualTo(wrong.getResponse().getContentAsString());
            assertThat(refused.getResponse().getHeaderNames()).isEqualTo(wrong.getResponse().getHeaderNames());
            verify(users, never()).save(any());
        }

        @Test
        @DisplayName("an account that can still sign in")
        void notExpired() throws Exception {
            assertAnswersAsWrong(post("right"));
        }

        @Test
        @DisplayName("a disabled account")
        void disabled() throws Exception {
            account.setEnabled(false);
            account.setCredentialsExpired(true);

            assertAnswersAsWrong(post("right"));
        }

        @Test
        @DisplayName("an expired account with a stored BLOCK")
        void blocked() throws Exception {
            account.setCredentialsExpired(true);
            actions.setBlockedFlag("alice");

            assertAnswersAsWrong(post("right"));
        }

        @Test
        @DisplayName("a session of another user")
        void anotherUser() throws Exception {
            SecurityContextHolder.getContext().setAuthentication(
                    UsernamePasswordAuthenticationToken.authenticated("mallory", null, AuthorityUtils.NO_AUTHORITIES));

            assertAnswersAsWrong(post("right"));
        }

        @Test
        @DisplayName("a session that waits for its MFA")
        void mfaPending() throws Exception {
            SecurityContextHolder.getContext().setAuthentication(
                    UsernamePasswordAuthenticationToken.authenticated("alice", null, AuthorityUtils.NO_AUTHORITIES));
            MockHttpSession session = new MockHttpSession();
            session.setAttribute(MfaPendingSession.ATTRIBUTE, "mfa");

            assertAnswersAsWrong(post("right", session));
        }

        @Test
        @DisplayName("a store that is down does not fail a change that went through: the answer is the success")
        void aStoreThatIsDown() throws Exception {
            account.setCredentialsExpired(true);
            when(encoder.encode("New-Pass-1")).thenReturn("{hash}new");
            doThrow(new IllegalStateException("store down")).when(dataStore).advanceAuthoritiesVersion();
            doThrow(new IllegalStateException("store down")).when(logout).forceLogoutByUserId(anyString(), anyString());

            assertChangedDespiteTheStore(post("right"));
            verify(logout).forceLogoutByUserId("alice", "PASSWORD_CHANGED");
        }

        /** Every call of Redis fails, through the repository, the store and the session service that run on it. */
        @Test
        @DisplayName("with Redis down the change of a user without a restriction goes through and the answer is the success")
        void redisIsDown() throws Exception {
            account.setCredentialsExpired(true);
            when(encoder.encode("New-Pass-1")).thenReturn("{hash}new");
            Answer<Object> down = call -> {
                throw new QueryTimeoutException("Redis command timed out");
            };
            RedisTemplate<String, Object> objects = mock(RedisTemplate.class, down);
            StringRedisTemplate strings = mock(StringRedisTemplate.class, down);
            ZeroTrustActionRedisRepository repository = new ZeroTrustActionRedisRepository(objects, strings);
            when(decisions.getIfAvailable()).thenReturn(repository);
            dataStore = new RedisSecurityContextDataStore(objects);
            logout = new RedisZeroTrustSecurityService(objects, mock(ThreatScoreUtil.class), new SecurityZeroTrustProperties(),
                    repository)::invalidateAllUserSessions;

            assertChangedDespiteTheStore(post("right"));
        }

        private void assertChangedDespiteTheStore(MvcResult changed) {
            assertThat(changed.getResolvedException()).isNull();
            assertThat(changed.getResponse().getStatus()).isEqualTo(302);
            assertThat(changed.getResponse().getRedirectedUrl()).isEqualTo("/contexa/admin/login");
            assertThat(account.getPassword()).isEqualTo("{hash}new");
            verify(users).save(account);
        }

        @Test
        @DisplayName("the form reads no account: a name that exists and one that does not get the same page")
        void theFormTellsNothing() throws Exception {
            when(passwordPolicyService.getCurrentPolicy()).thenReturn(new PasswordPolicy());

            for (String name : List.of("alice", "nobody")) {
                answering.perform(get("/contexa/password-change").param("username", name))
                        .andExpect(status().isOk())
                        .andExpect(view().name("contexa/password-change"))
                        .andExpect(model().attribute("username", name));
            }

            verifyNoInteractions(users, encoder);
        }
    }
}
