package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.SecurityPlaneAgent;
import io.contexa.contexacore.autonomous.event.SecurityEventPublisher;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.ZeroTrustEventListener;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService.AsyncProtectableGate;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.testsupport.AdjustableClock;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Whoever holds a person's session can change the browser string at each call, and each call from a changed context is
 * a decision of the model that someone pays for. The call goes on while it is analysed and never waits for the verdict,
 * but the decisions of new contexts a person may ask for in the window are limited: past them the call is refused with a
 * CHALLENGE of its own, the model is not asked and nothing is stored. The calls of the context on record go on as before.
 */
@DisplayName("The limit of the decisions a person can buy by changing context, without waiting for a verdict")
class ChangedContextLimitWithoutWaitTest {

    private static final String USER = "alice";
    private static final String HOME = "context-home";

    private final AdjustableClock clock = new AdjustableClock();
    private final InMemoryZeroTrustActionRepository repository =
            new InMemoryZeroTrustActionRepository(Duration.ofHours(24), clock);
    private final ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
    private final ZeroTrustEventListener listener = new ZeroTrustEventListener(mock(SecurityEventPublisher.class),
            repository, new SecurityZeroTrustProperties());
    private final SecurityPlaneAgent agent = mock(SecurityPlaneAgent.class);
    private final MethodInvocation invocation = mock(MethodInvocation.class);
    private final Authentication alice = new UsernamePasswordAuthenticationToken(USER, "n/a");
    private final ThreadLocal<Map<String, Object>> request = new ThreadLocal<>();
    private SynchronousProtectableDecisionService service;

    @BeforeEach
    void setUp() {
        SecurityZeroTrustProperties.NewContextLimit settings = new SecurityZeroTrustProperties.NewContextLimit();
        NewContextDecisionLimit limit = new NewContextDecisionLimit(settings, null, clock);
        service = new SynchronousProtectableDecisionService(publisher, listener, agent, repository);
        service.setUnanalysedRequestRecorder(mock(UnanalysedRequestRecorder.class));
        service.setNewContextDecisionLimit(limit);
        when(publisher.buildMethodAuthorizationEvent(any(MethodInvocation.class), any(Authentication.class), anyBoolean(), any()))
                .thenAnswer(call -> event(request.get()));
        repository.writeFinalAction(USER, ZeroTrustAction.ALLOW, Map.of("observationId", "observation-1", "processingGeneration", "1",
                "contextBindingHash", HOME));
    }

    private static ZeroTrustSpringEvent event(Map<String, Object> payload) {
        return ZeroTrustSpringEvent.builder(new Object()).category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType(ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD).userId(USER).sessionId("session-1")
                .clientIp("10.0.0.1").userAgent("browser").resource("/records/1").payload(payload).build();
    }

    private AsyncProtectableGate gate(String context) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("contextBindingHash", context);
        request.set(payload);
        return service.asyncGate(invocation, alice);
    }

    @Test
    @DisplayName("a call from the context on record goes on and takes nothing from the limit")
    void theContextOnRecordTakesNothing() {
        for (int i = 0; i < 20; i++) {
            assertThat(gate(HOME).restriction()).isNull();
        }
        assertThat(gate("context-new-0").restriction()).isNull();
    }

    @Test
    @DisplayName("the first contexts within the limit go on at once, without a wait for the model")
    void newContextsWithinTheLimitGoOnWithoutWaiting() {
        long began = System.nanoTime();
        for (int i = 0; i < 6; i++) {
            AsyncProtectableGate answer = gate("context-new-" + i);
            assertThat(answer.restriction()).as("context %d", i).isNull();
        }
        assertThat(Duration.ofNanos(System.nanoTime() - began)).isLessThan(Duration.ofSeconds(2));
    }

    @Test
    @DisplayName("past the limit a new context is refused with a CHALLENGE of its own and nothing is stored")
    void pastTheLimitANewContextIsChallenged() {
        for (int i = 0; i < 6; i++) {
            gate("context-new-" + i);
        }

        AsyncProtectableGate past = gate("context-new-6");

        assertThat(past.restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(repository.getCurrentAction(USER, HOME)).isEqualTo(ZeroTrustAction.ALLOW);
        assertThat(gate(HOME).restriction()).as("the context on record goes on").isNull();
    }

    @Test
    @DisplayName("the calls of one new context take from the limit once, and a context that was refused stays refused")
    void oneContextTakesOnce() {
        for (int i = 0; i < 5; i++) {
            gate("context-new-" + i);
        }
        // the sixth context asks twelve times at once and takes one place
        for (int i = 0; i < 12; i++) {
            assertThat(gate("context-new-5").restriction()).isNull();
        }
        // the seventh is past the limit, and stays so on every later call
        for (int i = 0; i < 3; i++) {
            assertThat(gate("context-new-6").restriction()).isEqualTo(ZeroTrustAction.CHALLENGE);
        }
    }

    @Test
    @DisplayName("a minute later the window has room again")
    void theWindowOpensAgain() {
        for (int i = 0; i < 7; i++) {
            gate("context-new-" + i);
        }
        clock.advance(Duration.ofSeconds(70));

        assertThat(gate("context-later").restriction()).isNull();
    }
}
