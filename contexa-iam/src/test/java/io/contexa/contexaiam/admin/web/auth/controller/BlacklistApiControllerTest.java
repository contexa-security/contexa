package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Type;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
@DisplayName("BlacklistApiController")
class BlacklistApiControllerTest {

    @Mock
    private BlockedUserService blockedUserService;

    private BlacklistApiController controller;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.getContext()
                .setAuthentication(new TestingAuthenticationToken("admin", "password"));
        controller = new BlacklistApiController(blockedUserService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Nested
    @DisplayName("controller DTO boundary")
    class ControllerDtoBoundary {

        @Test
        @DisplayName("public signatures do not expose Map or BlockedUser entity")
        void publicSignaturesDoNotExposeMapOrEntity() {
            Set<String> forbiddenTypeNames = Set.of(
                    "java.util.Map",
                    "io.contexa.contexaiam.domain.entity.BlockedUser"
            );

            for (Method method : BlacklistApiController.class.getDeclaredMethods()) {
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
    @DisplayName("listBlockedUsers preserves blocked-user JSON fields")
    void listBlockedUsersPreservesJsonFields() throws Exception {
        when(blockedUserService.getBlockedUsers()).thenReturn(List.of(sampleBlockedUser()));

        mockMvc.perform(get("/admin/api/blacklist")
                        .param("status", "BLOCKED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(7))
                .andExpect(jsonPath("$[0].userId").value("user-1"))
                .andExpect(jsonPath("$[0].username").value("alice"))
                .andExpect(jsonPath("$[0].requestId").value("req-1"))
                .andExpect(jsonPath("$[0].riskScore").value(0.91))
                .andExpect(jsonPath("$[0].confidence").value(0.82))
                .andExpect(jsonPath("$[0].reasoning").value("risk"))
                .andExpect(jsonPath("$[0].blockedAt").value("2026-04-21T10:15:30"))
                .andExpect(jsonPath("$[0].blockCount").value(3))
                .andExpect(jsonPath("$[0].status").value("BLOCKED"))
                .andExpect(jsonPath("$[0].sourceIp").value("203.0.113.10"))
                .andExpect(jsonPath("$[0].userAgent").value("browser"))
                .andExpect(jsonPath("$[0].mfaVerified").value(false));
    }

    @Test
    @DisplayName("getBlockDetail preserves detail JSON fields")
    void getBlockDetailPreservesJsonFields() throws Exception {
        when(blockedUserService.getBlockDetail(7L)).thenReturn(Optional.of(sampleBlockedUser()));

        mockMvc.perform(get("/admin/api/blacklist/7"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(7))
                .andExpect(jsonPath("$.userId").value("user-1"))
                .andExpect(jsonPath("$.status").value("BLOCKED"));
    }

    @Test
    @DisplayName("resolveBlock preserves success and validation JSON fields")
    void resolveBlockPreservesJsonFields() throws Exception {
        mockMvc.perform(post("/admin/api/blacklist/7/resolve")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "resolvedAction": "UNBLOCK",
                                  "reason": "verified"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.id").value(7))
                .andExpect(jsonPath("$.resolvedAction").value("UNBLOCK"))
                .andExpect(jsonPath("$.error").doesNotExist());

        verify(blockedUserService)
                .resolveBlockById(eq(7L), eq("admin"), eq("UNBLOCK"), eq("verified"));

        mockMvc.perform(post("/admin/api/blacklist/7/resolve")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"missing action\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error").value("resolvedAction is required"))
                .andExpect(jsonPath("$.id").doesNotExist());
    }

    @Test
    @DisplayName("resolveBlock rejects null body without server error")
    void resolveBlockRejectsNullBody() throws Exception {
        mockMvc.perform(post("/admin/api/blacklist/7/resolve")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("null"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error").value("request body is required"));
    }

    @Test
    @DisplayName("deleteBlockRecord preserves success and error JSON fields")
    void deleteBlockRecordPreservesJsonFields() throws Exception {
        mockMvc.perform(delete("/admin/api/blacklist/7"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.id").value(7))
                .andExpect(jsonPath("$.error").doesNotExist());

        doThrow(new RuntimeException("Cannot delete active block"))
                .when(blockedUserService).deleteBlockRecord(8L);

        mockMvc.perform(delete("/admin/api/blacklist/8"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error").value("Cannot delete active block"))
                .andExpect(jsonPath("$.id").doesNotExist());
    }

    private BlockedUser sampleBlockedUser() {
        return BlockedUser.builder()
                .id(7L)
                .userId("user-1")
                .username("alice")
                .requestId("req-1")
                .riskScore(0.91)
                .confidence(0.82)
                .reasoning("risk")
                .blockedAt(LocalDateTime.of(2026, 4, 21, 10, 15, 30))
                .blockCount(3)
                .status(BlockedUserStatus.BLOCKED)
                .sourceIp("203.0.113.10")
                .userAgent("browser")
                .mfaVerified(false)
                .build();
    }
}
