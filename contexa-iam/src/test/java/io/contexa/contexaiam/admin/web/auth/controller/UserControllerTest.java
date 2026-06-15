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

import io.contexa.contexacommon.entity.SystemSettings;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.modelmapper.ModelMapper;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.MessageSource;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("UserController")
class UserControllerTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private ModelMapper modelMapper;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private PasswordPolicyService passwordPolicyService;

    @Mock
    private MessageSource messageSource;

    @Mock
    private SystemSettingsService systemSettingsService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> inv.getArgument(0));
        UserController controller = new UserController(
                userRepository,
                modelMapper,
                passwordEncoder,
                passwordPolicyService,
                messageSource,
                systemSettingsService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Nested
    @DisplayName("controller DTO boundary")
    class ControllerDtoBoundary {

        @Test
        @DisplayName("processRegister signature does not expose wildcard or common UserDto")
        void processRegisterSignatureDoesNotExposeWildcardOrCommonUserDto() {
            Method method = Arrays.stream(UserController.class.getDeclaredMethods())
                    .filter(candidate -> candidate.getName().equals("processRegister"))
                    .findFirst()
                    .orElseThrow();

            assertThat(method.getGenericReturnType().getTypeName())
                    .doesNotContain("?")
                    .doesNotContain("java.lang.Object")
                    .doesNotContain("java.util.Map");
            Arrays.stream(method.getGenericParameterTypes())
                    .map(Type::getTypeName)
                    .forEach(typeName -> assertThat(typeName)
                            .doesNotContain("io.contexa.contexacommon.domain.UserDto"));
        }
    }

    @Test
    @DisplayName("processRegister preserves disabled-registration error JSON")
    void processRegisterRegistrationDisabled() throws Exception {
        when(systemSettingsService.getSettings()).thenReturn(SystemSettings.builder()
                .registrationEnabled(false)
                .build());

        mockMvc.perform(post("/contexa/api/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "alice",
                                  "password": "Password1!",
                                  "name": "Alice"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("msg.registration.disabled"))
                .andExpect(jsonPath("$.violations").doesNotExist());
    }

    @Test
    @DisplayName("processRegister preserves password-policy violation JSON")
    void processRegisterPasswordPolicyViolation() throws Exception {
        when(systemSettingsService.getSettings()).thenReturn(SystemSettings.builder()
                .registrationEnabled(true)
                .build());
        when(userRepository.findByUsername("alice")).thenReturn(Optional.empty());
        when(passwordPolicyService.validatePassword("weak")).thenReturn(List.of("too short"));

        mockMvc.perform(post("/contexa/api/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "alice",
                                  "password": "weak",
                                  "name": "Alice"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("msg.user.password.policy.violation"))
                .andExpect(jsonPath("$.violations[0]").value("too short"));
    }

    @Test
    @DisplayName("processRegister preserves success text body and delegates same user fields")
    void processRegisterSuccess() throws Exception {
        when(systemSettingsService.getSettings()).thenReturn(SystemSettings.builder()
                .registrationEnabled(true)
                .build());
        when(userRepository.findByUsername("alice")).thenReturn(Optional.empty());
        when(passwordPolicyService.validatePassword("Password1!")).thenReturn(List.of());
        Users mapped = new Users();
        mapped.setUsername("alice");
        mapped.setPassword("Password1!");
        mapped.setName("Alice");
        when(modelMapper.map(any(), eq(Users.class))).thenReturn(mapped);
        when(passwordEncoder.encode("Password1!")).thenReturn("encoded");

        mockMvc.perform(post("/contexa/api/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "alice",
                                  "password": "Password1!",
                                  "name": "Alice",
                                  "email": "alice@example.com"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(content().string("success"));

        verify(userRepository).save(argThat(user ->
                "alice".equals(user.getUsername())
                        && "encoded".equals(user.getPassword())
                        && user.isMfaEnabled()
                        && user.isEnabled()
                        && user.getPasswordChangedAt() != null));
    }
}
