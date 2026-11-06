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
package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.baseline.LearningSubject;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Q-18: a restriction of one spelling of a name reaches every spelling of it, in both stores. Each test uses names of
 * its own, so the Redis store runs beside other tests.
 */
abstract class AbstractZeroTrustActionRepositoryUserKeyContractTest {

    private static final String CONTEXT = "context-1";

    protected ZeroTrustActionRepository repository;
    private String name;
    private String capitals;
    private String fullWidth;

    protected abstract ZeroTrustActionRepository createRepository();

    @BeforeEach
    void setUpRepository() {
        repository = createRepository();
        name = "plain-" + UUID.randomUUID().toString().replace("-", "");
        capitals = name.toUpperCase(Locale.ROOT);
        fullWidth = "ｐ" + name.substring(1);
    }

    private static Map<String, Object> finalFields() {
        return Map.of("observationId", "observation-1", "processingGeneration", "1", "contextBindingHash", CONTEXT);
    }

    @Test
    @DisplayName("a BLOCK of one spelling stops every spelling, and the release of one lifts them all")
    void aBlockReachesEverySpelling() {
        repository.saveAction(name, ZeroTrustAction.BLOCK, Map.of());
        repository.setBlockedFlag(name);

        assertThat(repository.getCurrentAction(capitals, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getCurrentAction(fullWidth, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getCurrentAction(" " + name + " ", CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);

        repository.approveOverrideAtomically(capitals, ZeroTrustAction.ALLOW);

        assertThat(repository.getCurrentAction(name, CONTEXT)).isNotEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getCurrentAction(fullWidth, CONTEXT)).isNotEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("a CHALLENGE of one spelling is the decision of every spelling, and keeps out what is less strict")
    void aChallengeReachesEverySpelling() {
        assertThat(repository.saveFinalAction(capitals, ZeroTrustAction.CHALLENGE, finalFields())).isTrue();

        assertThat(repository.getCurrentAction(name, CONTEXT)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getActionFromHash(fullWidth)).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.writeFinalAction(name, ZeroTrustAction.ALLOW, finalFields()))
                .isEqualTo(ZeroTrustActionRepository.FinalActionWrite.KEPT_STRICTER);
    }

    @Test
    @DisplayName("what the analysis left is read under every spelling")
    void theAnalysisIsReadUnderEverySpelling() {
        repository.saveAction(name, ZeroTrustAction.ALLOW, Map.of("requestId", "request-1"));

        assertThat(repository.getAnalysisData(capitals).requestId()).isEqualTo("request-1");
        assertThat(repository.getLastVerifiedAction(fullWidth)).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("the state of a block's MFA and of an ESCALATE is one, whichever spelling touches it")
    void theStateAroundADecisionFollows() {
        repository.setBlockMfaPending(name);
        repository.incrementBlockMfaFailCount(capitals);
        repository.incrementBlockMfaFailCount(fullWidth);
        repository.setEscalateRetry(capitals, Duration.ofMinutes(1));
        repository.markDecisionAuditPending(name, CONTEXT, Duration.ofMinutes(1));

        assertThat(repository.isBlockMfaPending(capitals)).isTrue();
        assertThat(repository.getBlockMfaFailCount(name)).isEqualTo(2);
        assertThat(repository.hasEscalateRetry(fullWidth)).isTrue();
        assertThat(repository.isDecisionAuditPending(capitals, CONTEXT)).isTrue();

        repository.clearBlockMfaPending(capitals);
        repository.clearDecisionAuditPending(fullWidth, CONTEXT);

        assertThat(repository.isBlockMfaPending(name)).isFalse();
        assertThat(repository.isDecisionAuditPending(name, CONTEXT)).isFalse();
    }

    @Test
    @DisplayName("removing a user's data takes every spelling's")
    void removalReachesEverySpelling() {
        repository.saveAction(name, ZeroTrustAction.BLOCK, Map.of());
        repository.setBlockedFlag(name);

        repository.removeAllUserData(capitals);

        assertThat(repository.getCurrentAction(name, CONTEXT)).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("an agent's decisions stay under the person's every spelling when the account goes")
    void agentDataFollowsTheName() {
        String agentKey = ZeroTrustSubject.of(name, null) != null ? name + "::agent::Agent-1" : null;
        repository.saveAction(agentKey, ZeroTrustAction.CHALLENGE, Map.of());

        repository.removeAllAgentData(capitals);

        assertThat(repository.getActionFromHash(agentKey)).isNull();
    }

    @Test
    @DisplayName("a BLOCK of a person named as the console's key stays off the console, in every spelling of the name")
    void aPersonsBlockStaysOffTheConsole() {
        String console = ZeroTrustSubject.CONSOLE_KEY + name;
        repository.saveAction(console, ZeroTrustAction.ALLOW, Map.of());

        for (String spelling : List.of(console, console.toUpperCase(Locale.ROOT), " " + console + " ",
                "ｃｏｎｓｏｌｅ::" + name)) {
            String person = ZeroTrustUserKey.person(spelling);
            repository.saveAction(person, ZeroTrustAction.BLOCK, Map.of());
            repository.setBlockedFlag(person);

            assertThat(repository.getCurrentAction(console, CONTEXT)).as(spelling).isEqualTo(ZeroTrustAction.ALLOW);
        }
        assertThat(repository.getCurrentAction(ZeroTrustUserKey.person(console), CONTEXT))
                .isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("a BLOCK of the console, and of an agent, stays off the person named as their key")
    void aBlockOfAnInternalKeyStaysOffThePerson() {
        String console = ZeroTrustSubject.CONSOLE_KEY + name;
        String agent = LearningSubject.agentKey(name, "agent-1");
        for (String key : List.of(console, agent)) {
            repository.saveAction(key, ZeroTrustAction.BLOCK, Map.of());
            repository.setBlockedFlag(key);
            repository.setBlockMfaPending(key);
            repository.setEscalateRetry(key, Duration.ofMinutes(1));

            String person = ZeroTrustUserKey.person(key);
            assertThat(repository.getCurrentAction(person, CONTEXT)).as(key).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
            assertThat(repository.isBlockMfaPending(person)).as(key).isFalse();
            assertThat(repository.hasEscalateRetry(person)).as(key).isFalse();
        }
    }

    @Test
    @DisplayName("the removal of a person named as an internal key leaves that key's decisions")
    void aPersonsRemovalLeavesTheInternalKey() {
        String console = ZeroTrustSubject.CONSOLE_KEY + name;
        repository.saveAction(console, ZeroTrustAction.BLOCK, Map.of());
        repository.setBlockedFlag(console);
        repository.saveAction(ZeroTrustUserKey.person(console), ZeroTrustAction.BLOCK, Map.of());
        repository.setBlockedFlag(ZeroTrustUserKey.person(console));

        repository.removeAllUserData(ZeroTrustUserKey.person(console));

        assertThat(repository.getCurrentAction(console, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(repository.getCurrentAction(ZeroTrustUserKey.person(console), CONTEXT))
                .isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("removing a person's agents leaves those of a person whose name starts with an agent's key")
    void aPersonsAgentsStayOffThoseOfAnother() {
        String oddlyNamed = name + "::agent::x";
        String own = LearningSubject.agentKey(name, "x");
        String another = LearningSubject.agentKey(oddlyNamed, "bot");
        repository.saveAction(own, ZeroTrustAction.CHALLENGE, Map.of());
        repository.saveAction(another, ZeroTrustAction.CHALLENGE, Map.of());

        repository.removeAllAgentData(ZeroTrustUserKey.person(name));

        assertThat(repository.getActionFromHash(own)).isNull();
        assertThat(repository.getActionFromHash(another)).isEqualTo(ZeroTrustAction.CHALLENGE);

        repository.removeAllAgentData(ZeroTrustUserKey.person(oddlyNamed));

        assertThat(repository.getActionFromHash(another)).isNull();
    }

    @Test
    @DisplayName("with the setting off, names that differ by case are two people")
    void theSettingKeepsThemApart() {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setNormalizeUserKeys(false);
        ZeroTrustUserKey.bind(properties);
        try {
            repository.setBlockedFlag(name);

            assertThat(repository.getCurrentAction(name, CONTEXT)).isEqualTo(ZeroTrustAction.BLOCK);
            assertThat(repository.getCurrentAction(capitals, CONTEXT)).isNotEqualTo(ZeroTrustAction.BLOCK);
        } finally {
            repository.removeBlockedFlag(name);
            ZeroTrustUserKey.unbind(properties);
        }
    }
}
