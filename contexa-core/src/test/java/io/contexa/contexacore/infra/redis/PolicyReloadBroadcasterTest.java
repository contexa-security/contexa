package io.contexa.contexacore.infra.redis;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.redisson.api.RTopic;
import org.redisson.api.RedissonClient;
import org.redisson.api.listener.MessageListener;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PolicyReloadBroadcasterTest {

    @Mock private RedissonClient redissonClient;
    @Mock private RTopic topic;

    private MessageListener<String> capturedListener;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        when(redissonClient.getTopic("contexa:policy:reload-signal")).thenReturn(topic);
        when(topic.addListener(eq(String.class), any(MessageListener.class))).thenAnswer(inv -> {
            capturedListener = inv.getArgument(1);
            return 1;
        });
    }

    // ── 1. 브로드캐스트 ─────────────────────────────────────────

    @Nested
    @DisplayName("리로드 신호 브로드캐스트")
    class BroadcastTests {

        @Test
        @DisplayName("broadcastReload 호출 시 인스턴스 ID가 포함된 메시지를 발행함")
        void broadcastPublishesMessage() {
            Runnable callback = mock(Runnable.class);
            PolicyReloadBroadcaster broadcaster = new PolicyReloadBroadcaster(redissonClient, callback);

            broadcaster.broadcastReload();

            ArgumentCaptor<String> msgCaptor = ArgumentCaptor.forClass(String.class);
            verify(topic).publishAsync(msgCaptor.capture());
            assertThat(msgCaptor.getValue()).startsWith("POLICY_RELOAD:");
        }

        @Test
        @DisplayName("Redis 발행 실패 시에도 예외가 전파되지 않음")
        void broadcastHandlesPublishFailure() {
            Runnable callback = mock(Runnable.class);
            PolicyReloadBroadcaster broadcaster = new PolicyReloadBroadcaster(redissonClient, callback);
            when(topic.publishAsync(any())).thenThrow(new RuntimeException("Redis down"));

            broadcaster.broadcastReload();

            verify(callback, never()).run();
        }
    }

    // ── 2. 리스너 동작 ──────────────────────────────────────────

    @Nested
    @DisplayName("리스너 동작 검증")
    class ListenerTests {

        @Test
        @DisplayName("원격 인스턴스 메시지 수신 시 콜백을 실행함")
        void listenerExecutesCallback() {
            AtomicInteger callCount = new AtomicInteger(0);
            new PolicyReloadBroadcaster(redissonClient, callCount::incrementAndGet);

            capturedListener.onMessage("contexa:policy:reload-signal",
                    "POLICY_RELOAD:remote-instance-id");

            assertThat(callCount.get()).isEqualTo(1);
        }

        @Test
        @DisplayName("자기 자신이 발행한 메시지는 무시함")
        void listenerIgnoresSelfMessages() {
            AtomicInteger callCount = new AtomicInteger(0);
            PolicyReloadBroadcaster broadcaster = new PolicyReloadBroadcaster(
                    redissonClient, callCount::incrementAndGet);

            broadcaster.broadcastReload();

            ArgumentCaptor<String> msgCaptor = ArgumentCaptor.forClass(String.class);
            verify(topic).publishAsync(msgCaptor.capture());
            String selfMessage = msgCaptor.getValue();

            capturedListener.onMessage("contexa:policy:reload-signal", selfMessage);

            assertThat(callCount.get()).isEqualTo(0);
        }

        @Test
        @DisplayName("null 메시지는 무시함")
        void listenerIgnoresNullMessages() {
            AtomicInteger callCount = new AtomicInteger(0);
            new PolicyReloadBroadcaster(redissonClient, callCount::incrementAndGet);

            capturedListener.onMessage("contexa:policy:reload-signal", null);

            assertThat(callCount.get()).isEqualTo(0);
        }

        @Test
        @DisplayName("관련 없는 메시지는 무시함")
        void listenerIgnoresUnrelatedMessages() {
            AtomicInteger callCount = new AtomicInteger(0);
            new PolicyReloadBroadcaster(redissonClient, callCount::incrementAndGet);

            capturedListener.onMessage("contexa:policy:reload-signal", "SOME_OTHER_MESSAGE");

            assertThat(callCount.get()).isEqualTo(0);
        }

        @Test
        @DisplayName("콜백 예외 발생 시에도 리스너가 정상 동작함")
        void listenerHandlesCallbackException() {
            Runnable failingCallback = () -> { throw new RuntimeException("Callback failed"); };
            new PolicyReloadBroadcaster(redissonClient, failingCallback);

            capturedListener.onMessage("contexa:policy:reload-signal",
                    "POLICY_RELOAD:remote-id");

            // should not propagate exception
        }

        @Test
        @DisplayName("여러 원격 메시지를 수신하면 각각 콜백이 실행됨")
        void multipleRemoteMessagesTriggerCallback() {
            AtomicInteger callCount = new AtomicInteger(0);
            new PolicyReloadBroadcaster(redissonClient, callCount::incrementAndGet);

            capturedListener.onMessage("ch", "POLICY_RELOAD:instance-a");
            capturedListener.onMessage("ch", "POLICY_RELOAD:instance-b");
            capturedListener.onMessage("ch", "POLICY_RELOAD:instance-c");

            assertThat(callCount.get()).isEqualTo(3);
        }
    }

    // ── 3. 등록 ─────────────────────────────────────────────────

    @Nested
    @DisplayName("토픽 등록 검증")
    class RegistrationTests {

        @Test
        @DisplayName("생성자에서 올바른 토픽에 리스너를 등록함")
        void constructorRegistersListener() {
            new PolicyReloadBroadcaster(redissonClient, () -> {});

            verify(redissonClient).getTopic("contexa:policy:reload-signal");
            verify(topic).addListener(eq(String.class), any(MessageListener.class));
        }
    }
}
