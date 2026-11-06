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
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository.FinalActionWrite;
import io.contexa.contexacore.testsupport.RedisTestTemplates;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.data.redis.serializer.RedisSerializer;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * PR-72: the script of a final write checks and writes in one step, so its answer is the outcome of the write. A
 * later write of the same user that replaced it is not a failed write; a Redis that fails or gives no answer is.
 */
class ZeroTrustActionRedisRepositoryFinalWriteTest {

    private static final String USER = "alice";
    private static final Map<String, Object> FIELDS = Map.of(
            "contextBindingHash", "context-a", "observationId", "observation-a", "processingGeneration", "generation-a");

    @SuppressWarnings("unchecked")
    private final RedisTemplate<String, Object> objects = mock(RedisTemplate.class);
    private final StringRedisTemplate strings = mock(StringRedisTemplate.class);
    @SuppressWarnings("unchecked")
    private final HashOperations<String, Object, Object> hashes = mock(HashOperations.class);
    private final ZeroTrustActionRedisRepository repository = new ZeroTrustActionRedisRepository(objects, strings);

    @BeforeEach
    @SuppressWarnings({"unchecked", "rawtypes"})
    void serializersAsInProduction() {
        when(objects.getHashKeySerializer()).thenReturn((RedisSerializer) RedisSerializer.string());
        when(objects.getHashValueSerializer()).thenReturn((RedisSerializer) RedisSerializer.json());
        when(objects.opsForHash()).thenReturn(hashes);
    }

    @SuppressWarnings("unchecked")
    private void scriptAnswers(Long answer) {
        when(strings.execute(any(RedisScript.class), any(RedisSerializer.class), any(RedisSerializer.class), anyList(),
                any(Object[].class))).thenReturn(answer);
    }

    @Test
    void aWriteTheScriptMadeIsAppliedEvenWhenALaterWriteHasReplacedItAlready() {
        scriptAnswers(1L);
        when(hashes.entries(anyString())).thenReturn(Map.of("action", "ALLOW", "observationId", "observation-later",
                "processingGeneration", "generation-later"));

        assertThat(repository.writeFinalAction(USER, ZeroTrustAction.ALLOW, FIELDS)).isEqualTo(FinalActionWrite.APPLIED);
        assertThat(repository.saveFinalAction(USER, ZeroTrustAction.ALLOW, FIELDS)).isTrue();
    }

    @Test
    void aWriteTheScriptMadeIsNotReadBack() {
        scriptAnswers(1L);

        repository.writeFinalAction(USER, ZeroTrustAction.CHALLENGE, FIELDS);

        verifyNoInteractions(hashes);
    }

    @Test
    void aWriteTheScriptRefusedIsKeptOutByAStricterAction() {
        scriptAnswers(0L);

        assertThat(repository.writeFinalAction(USER, ZeroTrustAction.ALLOW, FIELDS))
                .isEqualTo(FinalActionWrite.KEPT_STRICTER);
        assertThat(repository.saveFinalAction(USER, ZeroTrustAction.ALLOW, FIELDS)).as("not a write to retry").isTrue();
    }

    @Test
    @SuppressWarnings("unchecked")
    void aRedisThatFailsDuringTheWriteIsAFailedWrite() {
        when(strings.execute(any(RedisScript.class), any(RedisSerializer.class), any(RedisSerializer.class), anyList(),
                any(Object[].class))).thenThrow(new RedisConnectionFailureException("connection lost"));

        assertThat(repository.writeFinalAction(USER, ZeroTrustAction.ALLOW, FIELDS)).isEqualTo(FinalActionWrite.FAILED);
        assertThat(repository.saveFinalAction(USER, ZeroTrustAction.ALLOW, FIELDS)).isFalse();
    }

    @Test
    void aScriptThatGaveNoAnswerIsAFailedWrite() {
        scriptAnswers(null);

        assertThat(repository.writeFinalAction(USER, ZeroTrustAction.ALLOW, FIELDS)).isEqualTo(FinalActionWrite.FAILED);
    }

    @Test
    void aRedisThatCannotBeReachedIsAFailedWrite() {
        LettuceConnectionFactory unreachable = new LettuceConnectionFactory("127.0.0.1", 1);
        unreachable.afterPropertiesSet();
        try {
            ZeroTrustActionRedisRepository down = new ZeroTrustActionRedisRepository(
                    RedisTestTemplates.newProductionAlignedRedisTemplate(unreachable),
                    RedisTestTemplates.newStringRedisTemplate(unreachable));

            assertThat(down.writeFinalAction(USER, ZeroTrustAction.ALLOW, FIELDS)).isEqualTo(FinalActionWrite.FAILED);
        } finally {
            unreachable.destroy();
        }
    }

    @Test
    void aDecisionWithoutItsObservationStaysAFailedWriteAndReachesNoScript() {
        assertThat(repository.writeFinalAction(USER, ZeroTrustAction.ALLOW, Map.of("contextBindingHash", "context-a")))
                .isEqualTo(FinalActionWrite.FAILED);

        verifyNoInteractions(strings);
    }
}
