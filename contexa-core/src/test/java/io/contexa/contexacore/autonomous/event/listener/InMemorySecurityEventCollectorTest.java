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
package io.contexa.contexacore.autonomous.event.listener;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.lang.reflect.Field;
import java.time.LocalDateTime;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class InMemorySecurityEventCollectorTest {

    @Mock
    private SecurityEventListener listener1;

    @Mock
    private SecurityEventListener listener2;

    private InMemorySecurityEventCollector collector;

    @BeforeEach
    void setUp() {
        collector = new InMemorySecurityEventCollector();
        when(listener1.isActive()).thenReturn(true);
        when(listener2.isActive()).thenReturn(true);
        when(listener1.getListenerName()).thenReturn("listener1");
        when(listener2.getListenerName()).thenReturn("listener2");
    }

    @Test
    @DisplayName("Should register and unregister listeners")
    void shouldRegisterAndUnregisterListeners() {
        // given / when
        collector.registerListener(listener1);
        collector.registerListener(listener2);

        // then
        Map<String, Object> stats = collector.getStatistics();
        assertThat(stats.get("listener_count")).isEqualTo(2);

        // when - unregister
        collector.unregisterListener(listener1);

        // then
        stats = collector.getStatistics();
        assertThat(stats.get("listener_count")).isEqualTo(1);
    }

    @Test
    @DisplayName("dispatchEvent should invoke all active listeners")
    void shouldDispatchEventToAllActiveListeners() {
        // given
        collector.registerListener(listener1);
        collector.registerListener(listener2);

        SecurityEvent event = SecurityEvent.builder()
                .eventId("evt-1")
                .build();

        // when
        collector.dispatchEvent(event);

        // then
        verify(listener1).onSecurityEvent(event);
        verify(listener2).onSecurityEvent(event);
    }

    @Test
    @DisplayName("캐시 한도를 넘기면 가장 오래된 timestamp 기준 이벤트부터 제거해야 한다")
    void shouldEvictOldestTimestampEntriesWhenCacheExceedsMaxSize() throws Exception {
        for (int i = 0; i < 10_001; i++) {
            SecurityEvent event = SecurityEvent.builder()
                    .eventId("evt-" + i)
                    .timestamp(LocalDateTime.now().plusSeconds(i))
                    .build();
            collector.dispatchEvent(event);
        }

        Map<String, Object> stats = collector.getStatistics();
        int cacheSize = (int) stats.get("cache_size");
        assertThat(cacheSize).isLessThanOrEqualTo(10_000);

        Field cacheField = InMemorySecurityEventCollector.class.getDeclaredField("eventCache");
        cacheField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, SecurityEvent> cache = (Map<String, SecurityEvent>) cacheField.get(collector);

        assertThat(cache).doesNotContainKey("evt-0");
        assertThat(cache).doesNotContainKey("evt-999");
        assertThat(cache).containsKey("evt-10000");
    }

    @Test
    @DisplayName("Statistics should track eventCount and errorCount")
    void shouldTrackStatistics() {
        collector.registerListener(listener1);
        doThrow(new RuntimeException("test error"))
                .when(listener1).onSecurityEvent(any());

        SecurityEvent event1 = SecurityEvent.builder().eventId("evt-1").build();
        SecurityEvent event2 = SecurityEvent.builder().eventId("evt-2").build();

        assertThatThrownBy(() -> collector.dispatchEvent(event1))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Listener dispatch failed");
        assertThatThrownBy(() -> collector.dispatchEvent(event2))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Listener dispatch failed");

        Map<String, Object> stats = collector.getStatistics();
        assertThat(stats.get("total_events")).isEqualTo(2L);
        assertThat(stats.get("error_count")).isEqualTo(2L);
    }

    @Test
    @DisplayName("Null event should be silently ignored")
    void shouldIgnoreNullEvent() {
        // given
        collector.registerListener(listener1);

        // when
        collector.dispatchEvent(null);

        // then
        verify(listener1, never()).onSecurityEvent(any());
        Map<String, Object> stats = collector.getStatistics();
        assertThat(stats.get("total_events")).isEqualTo(0L);
    }

    @Test
    @DisplayName("Should not register duplicate listeners")
    void shouldNotRegisterDuplicateListeners() {
        // given / when
        collector.registerListener(listener1);
        collector.registerListener(listener1);

        // then
        Map<String, Object> stats = collector.getStatistics();
        assertThat(stats.get("listener_count")).isEqualTo(1);
    }

    @Test
    @DisplayName("Should not dispatch to inactive listeners")
    void shouldNotDispatchToInactiveListeners() {
        // given
        when(listener1.isActive()).thenReturn(false);
        collector.registerListener(listener1);

        SecurityEvent event = SecurityEvent.builder().eventId("evt-1").build();

        // when
        collector.dispatchEvent(event);

        // then
        verify(listener1, never()).onSecurityEvent(any());
    }
}
