package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.MessageSource;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Type;
import java.util.Locale;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("PasswordPolicyController")
class PasswordPolicyControllerTest {

    @Mock
    private PasswordPolicyService passwordPolicyService;

    @Mock
    private MessageSource messageSource;

    private PasswordPolicyController controller;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        when(messageSource.getMessage(anyString(), any(), any(Locale.class)))
                .thenAnswer(inv -> inv.getArgument(0));
        controller = new PasswordPolicyController(passwordPolicyService, messageSource);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Nested
    @DisplayName("controller DTO boundary")
    class ControllerDtoBoundary {

        @Test
        @DisplayName("public signatures do not expose Map or PasswordPolicy entity")
        void publicSignaturesDoNotExposeMapOrEntity() {
            Set<String> forbiddenTypeNames = Set.of(
                    "java.util.Map",
                    "io.contexa.contexacommon.entity.PasswordPolicy"
            );

            for (Method method : PasswordPolicyController.class.getDeclaredMethods()) {
                if (!Modifier.isPublic(method.getModifiers())) {
                    continue;
                }
                assertNoForbiddenType(method.getGenericReturnType(), forbiddenTypeNames, method.toGenericString());
                for (Type parameterType : method.getGenericParameterTypes()) {
                    assertNoForbiddenType(parameterType, forbiddenTypeNames, method.toGenericString());
                }
            }
        }

        private void assertNoForbiddenType(Type type, Set<String> forbiddenTypeNames, String context) {
            String typeName = type.getTypeName();
            forbiddenTypeNames.forEach(forbidden ->
                    assertThat(typeName)
                            .as(context)
                            .doesNotContain(forbidden));
        }
    }

    @Test
    @DisplayName("showPolicy exposes a controller form DTO with the same field values")
    void showPolicyUsesControllerFormDto() {
        PasswordPolicy policy = samplePolicy();
        when(passwordPolicyService.getCurrentPolicy()).thenReturn(policy);
        Model model = new ConcurrentModel();

        String view = controller.showPolicy(model);

        assertThat(view).isEqualTo("admin/password-policy");
        assertThat(model.getAttribute("activePage")).isEqualTo("password-policy");
        Object form = model.getAttribute("policy");
        assertThat(form).isNotNull();
        assertThat(form.getClass().getName()).doesNotContain("contexacommon.entity.PasswordPolicy");
        assertThat(form).hasFieldOrPropertyWithValue("minLength", 12);
        assertThat(form).hasFieldOrPropertyWithValue("maxLength", 64);
        assertThat(form).hasFieldOrPropertyWithValue("requireUppercase", true);
        assertThat(form).hasFieldOrPropertyWithValue("requireLowercase", false);
        assertThat(form).hasFieldOrPropertyWithValue("requireDigit", true);
        assertThat(form).hasFieldOrPropertyWithValue("requireSpecialChar", true);
        assertThat(form).hasFieldOrPropertyWithValue("maxFailedAttempts", 4);
        assertThat(form).hasFieldOrPropertyWithValue("lockoutDurationMinutes", 15);
        assertThat(form).hasFieldOrPropertyWithValue("passwordExpiryDays", 45);
        assertThat(form).hasFieldOrPropertyWithValue("historyCount", 6);
    }

    @Test
    @DisplayName("getPolicyRules preserves existing JSON fields")
    void getPolicyRulesPreservesJsonFields() throws Exception {
        when(passwordPolicyService.getCurrentPolicy()).thenReturn(samplePolicy());

        mockMvc.perform(get("/admin/password-policy/api/rules"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.minLength").value(12))
                .andExpect(jsonPath("$.maxLength").value(64))
                .andExpect(jsonPath("$.requireUppercase").value(true))
                .andExpect(jsonPath("$.requireLowercase").value(false))
                .andExpect(jsonPath("$.requireDigit").value(true))
                .andExpect(jsonPath("$.requireSpecialChar").value(true));
    }

    @Test
    @DisplayName("updatePolicy binds existing form field names and delegates unchanged values")
    void updatePolicyBindsExistingFormFieldNames() throws Exception {
        mockMvc.perform(post("/admin/password-policy")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("minLength", "10")
                        .param("maxLength", "80")
                        .param("requireUppercase", "true")
                        .param("_requireLowercase", "on")
                        .param("requireDigit", "true")
                        .param("_requireSpecialChar", "on")
                        .param("maxFailedAttempts", "3")
                        .param("lockoutDurationMinutes", "20")
                        .param("passwordExpiryDays", "30")
                        .param("historyCount", "5"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/password-policy"))
                .andExpect(flash().attribute("message", "msg.password.policy.updated"));

        verify(passwordPolicyService).updatePolicy(argThat(policy ->
                policy.getMinLength() == 10
                        && policy.getMaxLength() == 80
                        && policy.isRequireUppercase()
                        && !policy.isRequireLowercase()
                        && policy.isRequireDigit()
                        && !policy.isRequireSpecialChar()
                        && policy.getMaxFailedAttempts() == 3
                        && policy.getLockoutDurationMinutes() == 20
                        && policy.getPasswordExpiryDays() == 30
                        && policy.getHistoryCount() == 5));
    }

    private PasswordPolicy samplePolicy() {
        return PasswordPolicy.builder()
                .minLength(12)
                .maxLength(64)
                .requireUppercase(true)
                .requireLowercase(false)
                .requireDigit(true)
                .requireSpecialChar(true)
                .maxFailedAttempts(4)
                .lockoutDurationMinutes(15)
                .passwordExpiryDays(45)
                .historyCount(6)
                .build();
    }
}
