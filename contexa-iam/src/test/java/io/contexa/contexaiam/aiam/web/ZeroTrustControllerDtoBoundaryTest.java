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
package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.aiam.event.ZeroTrustSsePublisher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
@DisplayName("Zero Trust controllers DTO boundary")
class ZeroTrustControllerDtoBoundaryTest {

    @Mock
    private ZeroTrustSsePublisher ssePublisher;

    @Mock
    private BlockedUserService blockedUserService;

    @Mock
    private BlockMfaStateStore blockMfaStateStore;

    @Test
    @DisplayName("SSE status preserves existing JSON fields")
    void sseStatusPreservesExistingJsonFields() throws Exception {
        when(ssePublisher.getSubscriberCount("alice")).thenReturn(3);
        MockMvc mockMvc = MockMvcBuilders
                .standaloneSetup(new ZeroTrustSseController(ssePublisher))
                .build();

        mockMvc.perform(get("/contexa/admin/api/aiam/sse/zero-trust/status")
                        .principal(() -> "alice"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("alice"))
                .andExpect(jsonPath("$.subscriberCount").value(3));
    }

    @Test
    @DisplayName("initiate block MFA preserves unauthenticated JSON")
    void initiateBlockMfaPreservesUnauthenticatedJson() throws Exception {
        MockMvc mockMvc = MockMvcBuilders
                .standaloneSetup(newZeroTrustUnblockController())
                .build();

        mockMvc.perform(post("/contexa/admin/api/aiam/zero-trust/initiate-block-mfa"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("Authentication required"));
    }

    @Test
    @DisplayName("initiate block MFA preserves success JSON")
    void initiateBlockMfaPreservesSuccessJson() throws Exception {
        when(blockMfaStateStore.getFailCount("alice")).thenReturn(0);
        MockMvc mockMvc = MockMvcBuilders
                .standaloneSetup(newZeroTrustUnblockController())
                .build();

        mockMvc.perform(post("/contexa/admin/api/aiam/zero-trust/initiate-block-mfa")
                        .principal(() -> "alice"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").doesNotExist())
                .andExpect(jsonPath("$.mfaVerified").doesNotExist());

        verify(blockMfaStateStore).setPending("alice");
    }

    @Test
    @DisplayName("unblock request preserves MFA-required JSON")
    void unblockRequestPreservesMfaRequiredJson() throws Exception {
        when(blockMfaStateStore.isVerified("alice")).thenReturn(false);
        MockMvc mockMvc = MockMvcBuilders
                .standaloneSetup(newZeroTrustUnblockController())
                .build();

        mockMvc.perform(post("/contexa/admin/api/aiam/zero-trust/unblock-request")
                        .principal(() -> "alice")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"resolved\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("MFA verification required before unblock request"));
    }

    @Test
    @DisplayName("unblock request preserves success JSON")
    void unblockRequestPreservesSuccessJson() throws Exception {
        when(blockMfaStateStore.isVerified("alice")).thenReturn(true);
        MockMvc mockMvc = MockMvcBuilders
                .standaloneSetup(newZeroTrustUnblockController())
                .build();

        mockMvc.perform(post("/contexa/admin/api/aiam/zero-trust/unblock-request")
                        .principal(() -> "alice")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"resolved\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.mfaVerified").value(true))
                .andExpect(jsonPath("$.message").value("Unblock request submitted"));

        verify(blockedUserService).requestUnblockWithMfa("alice", "resolved", true);
    }

    private ZeroTrustUnblockController newZeroTrustUnblockController() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setMaxBlockMfaAttempts(2);
        return new ZeroTrustUnblockController(blockedUserService, blockMfaStateStore, properties);
    }
}
