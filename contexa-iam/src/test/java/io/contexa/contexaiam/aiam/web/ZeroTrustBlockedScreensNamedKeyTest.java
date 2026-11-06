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
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.auth.service.BlockedUserService;
import io.contexa.contexaiam.aiam.web.dto.UnblockRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.ui.ExtendedModelMap;

import java.security.Principal;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** What a blocked user does on the screens of a block is the user's own, whatever the user is called. */
class ZeroTrustBlockedScreensNamedKeyTest {

    private static final String NAME = "console::rcboss";
    private static final String OWN = ZeroTrustUserKey.person(NAME);

    private final BlockMfaStateStore blockMfa = mock(BlockMfaStateStore.class);
    private final BlockedUserService blocks = mock(BlockedUserService.class);
    private final SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
    private final Principal user = () -> NAME;

    @Test
    @DisplayName("the blocked screen reads the user's own state, not the console's")
    void theBlockedScreenReadsTheUsersState() {
        new ZeroTrustPageController(blockMfa, blocks, properties).blocked(user, new ExtendedModelMap(),
                new MockHttpServletRequest());

        verify(blockMfa).getFailCount(OWN);
        verify(blockMfa).isVerified(OWN);
        verify(blockMfa, never()).isVerified(NAME);
        verify(blocks).hasLatestStatus(eq(OWN), any());
    }

    @Test
    @DisplayName("starting the MFA of a block marks the user's own key, not the console's")
    void theMfaOfABlockStartsForTheUser() {
        new ZeroTrustUnblockController(blocks, blockMfa, properties).initiateBlockMfa(user);

        verify(blockMfa).setPending(OWN);
        verify(blockMfa, never()).setPending(NAME);
    }

    @Test
    @DisplayName("the request to unblock is the user's own, not the console's")
    void theUnblockRequestIsTheUsers() {
        when(blockMfa.isVerified(OWN)).thenReturn(true);
        UnblockRequest request = new UnblockRequest();
        request.setReason("it was me");

        new ZeroTrustUnblockController(blocks, blockMfa, properties).requestUnblock(user, request);

        verify(blocks).requestUnblockWithMfa(OWN, "it was me", true);
    }
}
