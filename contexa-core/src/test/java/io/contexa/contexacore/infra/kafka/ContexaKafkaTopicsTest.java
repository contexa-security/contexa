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
package io.contexa.contexacore.infra.kafka;

import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.CreateTopicsResult;
import org.apache.kafka.clients.admin.ListTopicsResult;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.common.KafkaFuture;
import org.apache.kafka.common.errors.TimeoutException;
import org.apache.kafka.common.errors.TopicAuthorizationException;
import org.apache.kafka.common.errors.TopicExistsException;
import org.apache.kafka.common.internals.KafkaFutureImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.time.Duration;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * PR-73, PR-79: Contexa's topics are there before its consumer joins; what cannot be made is named at start, once, and
 * the application starts all the same.
 */
@ExtendWith(OutputCaptureExtension.class)
class ContexaKafkaTopicsTest {

    private static final String LOGIN = "security.events.authentication.success";
    private static final String CALL = "security.events.authorization.method";
    private static final String UNUSED = "network-events";
    private static final List<NewTopic> TOPICS = List.of(topic(LOGIN), topic(CALL), topic(UNUSED));
    private static final Set<String> NEEDED = Set.of(LOGIN, CALL);

    private final Admin admin = mock(Admin.class);

    private static NewTopic topic(String name) {
        return new NewTopic(name, Optional.empty(), Optional.empty());
    }

    private ContexaKafkaTopics topics(boolean create) {
        return new ContexaKafkaTopics(() -> admin, TOPICS, NEEDED, create);
    }

    private void brokerHolds(String... names) {
        ListTopicsResult listed = mock(ListTopicsResult.class);
        when(listed.names()).thenReturn(KafkaFuture.completedFuture(Set.of(names)));
        when(admin.listTopics()).thenReturn(listed);
    }

    private void creationEnds(Function<String, Throwable> failureOf) {
        when(admin.createTopics(anyCollection())).thenAnswer(call -> {
            Collection<NewTopic> asked = call.getArgument(0);
            CreateTopicsResult result = mock(CreateTopicsResult.class);
            Map<String, KafkaFuture<Void>> ends = new HashMap<>();
            for (NewTopic topic : asked) {
                KafkaFutureImpl<Void> end = new KafkaFutureImpl<>();
                Throwable failure = failureOf.apply(topic.name());
                if (failure != null) {
                    end.completeExceptionally(failure);
                } else {
                    end.complete(null);
                }
                ends.put(topic.name(), end);
            }
            when(result.values()).thenReturn(ends);
            return result;
        });
    }

    @Test
    void whatTheBrokerLacksIsMadeAndNothingElse() {
        brokerHolds(CALL);
        creationEnds(name -> null);

        assertThat(topics(true).provision()).isEmpty();

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Collection<NewTopic>> asked = ArgumentCaptor.forClass(Collection.class);
        verify(admin).createTopics(asked.capture());
        assertThat(asked.getValue().stream().map(NewTopic::name).collect(Collectors.toSet()))
                .containsExactlyInAnyOrder(LOGIN, UNUSED);
    }

    @Test
    void aBrokerThatHoldsEverythingIsLeftAlone(CapturedOutput output) {
        brokerHolds(LOGIN, CALL, UNUSED);

        topics(true).afterSingletonsInstantiated();

        verify(admin, never()).createTopics(anyCollection());
        assertThat(output.getOut() + output.getErr()).doesNotContain("[ContexaKafkaTopics]");
    }

    @Test
    void anotherNodeThatMadeTheTopicFirstIsNoFailure() {
        brokerHolds();
        creationEnds(name -> new TopicExistsException("made by another node"));

        assertThat(topics(true).provision()).isEmpty();
    }

    @Test
    void aTopicTheBrokerRefusesIsNamedOnOneErrorLine(CapturedOutput output) {
        brokerHolds(CALL);
        creationEnds(name -> new TopicAuthorizationException("not authorized to create " + name));

        topics(true).afterSingletonsInstantiated();

        assertThat(errorLines(output)).hasSize(1);
        assertThat(errorLines(output).get(0)).contains(LOGIN).doesNotContain(CALL)
                .contains("TopicAuthorizationException");
    }

    @Test
    void aTopicNothingWritesToIsNoAlarm(CapturedOutput output) {
        brokerHolds(LOGIN, CALL);
        creationEnds(name -> new TopicAuthorizationException("not authorized"));

        topics(true).afterSingletonsInstantiated();

        assertThat(errorLines(output)).isEmpty();
    }

    @Test
    void aBrokerThatDoesNotAnswerIsReportedAndTheStartGoesOn(CapturedOutput output) {
        ListTopicsResult listed = mock(ListTopicsResult.class);
        KafkaFutureImpl<Set<String>> never = new KafkaFutureImpl<>();
        never.completeExceptionally(new TimeoutException("no broker answered"));
        when(listed.names()).thenReturn(never);
        when(admin.listTopics()).thenReturn(listed);

        topics(true).afterSingletonsInstantiated();

        assertThat(errorLines(output)).hasSize(1);
        assertThat(errorLines(output).get(0)).contains(LOGIN).contains(CALL).contains("TimeoutException");
    }

    @Test
    void anAdminThatCannotBeMadeIsReportedAndTheStartGoesOn(CapturedOutput output) {
        ContexaKafkaTopics topics = new ContexaKafkaTopics(() -> {
            throw new IllegalArgumentException("no resolvable bootstrap urls");
        }, TOPICS, NEEDED, true);

        topics.afterSingletonsInstantiated();

        assertThat(errorLines(output)).hasSize(1);
        assertThat(errorLines(output).get(0)).contains(LOGIN).contains(CALL);
    }

    @Test
    void anApplicationThatForbidsMakingTopicsIsObeyedAndToldWhatIsMissing(CapturedOutput output) {
        brokerHolds(CALL);

        topics(false).afterSingletonsInstantiated();

        verify(admin, never()).createTopics(anyCollection());
        assertThat(errorLines(output)).hasSize(1);
        assertThat(errorLines(output).get(0)).contains(LOGIN).contains("auto-create");
    }

    @Test
    void theAdminIsClosedEvenWhenTheBrokerFails() {
        when(admin.listTopics()).thenThrow(new IllegalStateException("closed"));

        topics(true).provision();

        verify(admin).close(any(Duration.class));
    }

    @Test
    void anAdminThatFailsToCloseDoesNotStopTheStart() {
        brokerHolds(LOGIN, CALL, UNUSED);
        doThrow(new IllegalStateException("interrupted")).when(admin).close(any(Duration.class));

        assertThat(topics(true).provision()).isEmpty();
    }

    private static List<String> errorLines(CapturedOutput output) {
        return (output.getOut() + output.getErr()).lines()
                .filter(line -> line.contains("[ContexaKafkaTopics]"))
                .toList();
    }
}
