package io.contexa.contexacore.std.llm.gate;

import io.contexa.contexacore.properties.ModelServerGateProperties;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * How many analyses may run at once: a call waits at a model server's gate at most until the event's deadline, so no more
 * analyses may be in flight than the narrowest gate can serve within it. The limit follows the gates, a few times their
 * slots, and limits nothing where no gate is known to limit.
 */
class ModelServerGatesAnalysisConcurrencyTest {

    private static final int CHAT_CALLS = 6;
    private static final double SAFETY = 1.5;
    private static final long BUDGET_MS = 180_000L;
    private static final ModelServer LOCAL = ModelServer.of("ollama", "http://localhost:11434");
    private static final ModelServer REMOTE = ModelServer.of("anthropic", "https://api.anthropic.com");

    private final ModelServerGateProperties properties = new ModelServerGateProperties();
    private final AtomicReference<ModelServer> resolved = new AtomicReference<>(LOCAL);
    private final ModelServerGates gates = new ModelServerGates((model, kind) -> resolved.get(), properties, BUDGET_MS);

    private int limit() {
        return gates.analysisConcurrency(CHAT_CALLS, SAFETY);
    }

    @Test
    void gatesThatAreOffLimitNothing() {
        properties.setEnabled(false);

        assertThat(limit()).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void beforeAnyServerIsKnownTheNarrowestConfiguredLimitDecidesAndTheFirstWaveIsTwoForEachSlot() {
        // 2 calls at once on a self-hosted server, 16 on a remote one: the first wave is the narrow one
        assertThat(limit()).isEqualTo(2 * 2);

        properties.setSelfHostedMaxConcurrent(0);
        assertThat(limit()).isEqualTo(16 * 2);

        properties.setRemoteMaxConcurrent(0);
        assertThat(limit()).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void beforeAnyCallIsMeasuredAKnownServerKeepsTheFirstWave() {
        ModelServerGate gate = gates.gateFor(new Object(), CallKind.CHAT);

        assertThat(gate.chatCallMillis()).isZero();
        assertThat(limit()).isEqualTo(2 * 2);

        resolved.set(REMOTE);
        gates.gateFor(new Object(), CallKind.CHAT);
        assertThat(limit()).isEqualTo(2 * 2);
    }

    /** slots x budget / (chat calls x call time x safety): a call of 4 s on 2 slots, 180 s: 2 x 180 / (6 x 4 x 1.5) = 10. */
    @Test
    void theMeasuredTimeOfAChatCallSetsTheLimit() {
        ModelServerGate gate = gates.gateFor(new Object(), CallKind.CHAT);

        gate.recordChatCall(TimeUnit.SECONDS.toNanos(4));
        assertThat(limit()).isEqualTo(10);
    }

    @Test
    void aSlowerModelAllowsFewerAnalyses() {
        ModelServerGate gate = gates.gateFor(new Object(), CallKind.CHAT);

        // a call of 6.5 s: 2 x 180 / (6 x 6.5 x 1.5) = 6
        gate.recordChatCall(TimeUnit.MILLISECONDS.toNanos(6_500));

        assertThat(limit()).isEqualTo(6);
    }

    @Test
    void aFastRemoteServerAllowsFarMoreThanTheStripes() {
        resolved.set(REMOTE);
        ModelServerGate gate = gates.gateFor(new Object(), CallKind.CHAT);

        gate.recordChatCall(TimeUnit.SECONDS.toNanos(4));

        // 16 x 180 / (6 x 4 x 1.5) = 80
        assertThat(limit()).isEqualTo(80);
    }

    /** The slots are never left idle while an analysis prepares its next call, so at least two analyses for each slot. */
    @Test
    void theLimitNeverFallsBelowTwiceTheSlotsOfTheGate() {
        ModelServerGate gate = gates.gateFor(new Object(), CallKind.CHAT);

        gate.recordChatCall(TimeUnit.SECONDS.toNanos(120));

        assertThat(limit()).isEqualTo(2 * 2);
    }

    @Test
    void theNarrowestKnownServerDecides() {
        resolved.set(REMOTE);
        ModelServerGate remote = gates.gateFor(new Object(), CallKind.CHAT);
        remote.recordChatCall(TimeUnit.SECONDS.toNanos(4));
        resolved.set(LOCAL);
        ModelServerGate local = gates.gateFor(new Object(), CallKind.EMBEDDING);
        local.recordChatCall(TimeUnit.MILLISECONDS.toNanos(6_500));

        assertThat(limit()).isEqualTo(6);
    }

    @Test
    void aServerSetToNoLimitIsNotCounted() {
        properties.setSelfHostedMaxConcurrent(0);
        gates.gateFor(new Object(), CallKind.CHAT);

        assertThat(limit()).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void aCallToAServerThatPassesNoGateLimitsNothing() {
        resolved.set(null);
        gates.gateFor(new Object(), CallKind.CHAT);

        assertThat(limit()).isEqualTo(Integer.MAX_VALUE);
    }
}
