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

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
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
    @DisplayName("LRU cache should evict entries when exceeding 10K limit")
    void shouldEvictWhenCacheExceedsMaxSize() {
        // given - fill cache to max
        for (int i = 0; i < 10_001; i++) {
            SecurityEvent event = SecurityEvent.builder()
                    .eventId("evt-" + i)
                    .build();
            collector.dispatchEvent(event);
        }

        // then - cache size should be reduced after eviction batch
        Map<String, Object> stats = collector.getStatistics();
        int cacheSize = (int) stats.get("cache_size");
        // After eviction of 1000 entries: 10001 - 1000 + 1 (new entry) = 9001 approx
        assertThat(cacheSize).isLessThanOrEqualTo(10_000);
    }

    @Test
    @DisplayName("Statistics should track eventCount and errorCount")
    void shouldTrackStatistics() {
        // given
        collector.registerListener(listener1);
        doThrow(new RuntimeException("test error"))
                .when(listener1).onSecurityEvent(any());

        SecurityEvent event1 = SecurityEvent.builder().eventId("evt-1").build();
        SecurityEvent event2 = SecurityEvent.builder().eventId("evt-2").build();

        // when
        collector.dispatchEvent(event1);
        collector.dispatchEvent(event2);

        // then
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
