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
package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/** Q-1: the last way out of a CHALLENGE for a user with no factor is an administrator. */
class BlockedUserServiceChallengeReleaseTest {

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final AdminOverrideService overrides = mock(AdminOverrideService.class);
    private final CentralAuditFacade audit = mock(CentralAuditFacade.class);
    private final BlockingSignalBroadcaster signals = mock(BlockingSignalBroadcaster.class);
    private final BlockedUserService service = new BlockedUserService(mock(BlockedUserJpaRepository.class), overrides,
            actions, mock(ApplicationEventPublisher.class), audit, signals, mock(MessageSource.class));

    @Test
    @DisplayName("a CHALLENGE is lifted for every session, recorded in the audit, and nothing is learned from it")
    void aChallengeIsLifted() {
        actions.saveAction("no-mail", ZeroTrustAction.CHALLENGE, Map.of());

        assertThat(service.releaseChallenge(" no-mail ", "admin", "called the user")).isTrue();

        assertThat(actions.getActionFromHash("no-mail")).isEqualTo(ZeroTrustAction.ALLOW);
        verify(signals).registerUnblock("no-mail");
        verifyNoInteractions(overrides);
        ArgumentCaptor<AuditRecord> record = ArgumentCaptor.forClass(AuditRecord.class);
        verify(audit).recordAsync(record.capture());
        assertThat(record.getValue().getPrincipalName()).isEqualTo("admin");
        assertThat(record.getValue().getReason()).isEqualTo("called the user");
    }

    @Test
    @DisplayName("a name in the form of the console's key releases that person's CHALLENGE and leaves the console's")
    void theFormNamesThePersonFirst() {
        String person = ZeroTrustUserKey.person("console::rcboss");
        actions.saveAction(person, ZeroTrustAction.CHALLENGE, Map.of());
        actions.saveAction("console::rcboss", ZeroTrustAction.CHALLENGE, Map.of());

        assertThat(service.releaseChallenge("console::rcboss", "admin", "called the user")).isTrue();

        assertThat(actions.getActionFromHash(person)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(actions.getActionFromHash("console::rcboss")).isEqualTo(ZeroTrustAction.CHALLENGE);
        verify(signals).registerUnblock(person);
    }

    @Test
    @DisplayName("a console session's CHALLENGE is named by its key when no person of that name is challenged")
    void aConsoleChallengeIsNamedByItsKey() {
        actions.saveAction("console::rcboss", ZeroTrustAction.CHALLENGE, Map.of());

        assertThat(service.releaseChallenge("console::rcboss", "admin", "called the administrator")).isTrue();

        assertThat(actions.getActionFromHash("console::rcboss")).isEqualTo(ZeroTrustAction.ALLOW);
        verify(signals).registerUnblock("console::rcboss");
    }

    @Test
    @DisplayName("what other sessions still hold after one answered is lifted too")
    void whatIsHeldIsLifted() {
        actions.saveAction("no-mail", ZeroTrustAction.CHALLENGE, Map.of());
        actions.holdChallengeForOtherSessions("no-mail", "context-a");
        actions.saveActionWithPrevious("no-mail", ZeroTrustAction.ALLOW, "context-a");

        assertThat(service.releaseChallenge("no-mail", "admin", "called the user")).isTrue();

        assertThat(actions.getCurrentAction("no-mail", "context-b")).isNotEqualTo(ZeroTrustAction.CHALLENGE);
    }

    @Test
    @DisplayName("nothing to release says so and changes nothing")
    void nothingToRelease() {
        assertThat(service.releaseChallenge("no-mail", "admin", "called the user")).isFalse();

        verify(audit, never()).recordAsync(any());
    }

    @Test
    @DisplayName("a BLOCK is not lifted this way: it has its own way out")
    void aBlockStays() {
        actions.saveAction("no-mail", ZeroTrustAction.BLOCK, Map.of());
        actions.setBlockedFlag("no-mail");

        assertThat(service.releaseChallenge("no-mail", "admin", "called the user")).isFalse();

        assertThat(actions.getCurrentAction("no-mail", "context-a")).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("a release says who and why")
    void aReleaseSaysWhoAndWhy() {
        assertThatThrownBy(() -> service.releaseChallenge("no-mail", "admin", " "))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
