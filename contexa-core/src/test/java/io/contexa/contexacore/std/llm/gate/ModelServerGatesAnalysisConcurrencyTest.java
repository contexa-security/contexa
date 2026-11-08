package io.contexa.contexacore.std.llm.gate;

import io.contexa.contexacore.properties.ModelServerGateProperties;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * How many analyses may run at once: a call waits at a model server's gate at most until the event's deadline, so no more
 * analyses may be in flight than the narrowest gate can serve within it. The limit follows the gates, a few times their
 * slots, and limits nothing where no gate is known to limit.
 */
class ModelServerGatesAnalysisConcurrencyTest {

    private static final int PER_SLOT = 4;
    private static final ModelServer LOCAL = ModelServer.of("ollama", "http://localhost:11434");
    private static final ModelServer REMOTE = ModelServer.of("anthropic", "https://api.anthropic.com");

    private final ModelServerGateProperties properties = new ModelServerGateProperties();
    private final AtomicReference<ModelServer> resolved = new AtomicReference<>(LOCAL);
    private final ModelServerGates gates = new ModelServerGates((model, kind) -> resolved.get(), properties, 180_000L);

    @Test
    void gatesThatAreOffLimitNothing() {
        properties.setEnabled(false);

        assertThat(gates.analysisConcurrency(PER_SLOT)).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void beforeAnyServerIsKnownTheNarrowestConfiguredLimitDecides() {
        // 2 calls at once on a self-hosted server, 16 on a remote one: the first wave is the narrow one
        assertThat(gates.analysisConcurrency(PER_SLOT)).isEqualTo(2 * PER_SLOT);

        properties.setSelfHostedMaxConcurrent(0);
        assertThat(gates.analysisConcurrency(PER_SLOT)).isEqualTo(16 * PER_SLOT);

        properties.setRemoteMaxConcurrent(0);
        assertThat(gates.analysisConcurrency(PER_SLOT)).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void onceARemoteServerIsTheOnlyOneKnownItsOwnLimitDecides() {
        resolved.set(REMOTE);
        gates.gateFor(new Object(), CallKind.CHAT);

        assertThat(gates.analysisConcurrency(PER_SLOT)).isEqualTo(16 * PER_SLOT);
    }

    @Test
    void onceASelfHostedServerIsKnownItsLimitDecides() {
        gates.gateFor(new Object(), CallKind.CHAT);

        assertThat(gates.analysisConcurrency(PER_SLOT)).isEqualTo(2 * PER_SLOT);
    }

    @Test
    void theNarrowestKnownServerDecides() {
        resolved.set(REMOTE);
        gates.gateFor(new Object(), CallKind.CHAT);
        resolved.set(LOCAL);
        gates.gateFor(new Object(), CallKind.EMBEDDING);

        assertThat(gates.analysisConcurrency(PER_SLOT)).isEqualTo(2 * PER_SLOT);
    }

    @Test
    void aServerSetToNoLimitIsNotCounted() {
        properties.setSelfHostedMaxConcurrent(0);
        gates.gateFor(new Object(), CallKind.CHAT);

        assertThat(gates.analysisConcurrency(PER_SLOT)).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void aCallToAServerThatPassesNoGateLimitsNothing() {
        resolved.set(null);
        gates.gateFor(new Object(), CallKind.CHAT);

        assertThat(gates.analysisConcurrency(PER_SLOT)).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void theLimitIsAtLeastOneAnalysis() {
        properties.setSelfHostedMaxConcurrent(1);
        gates.gateFor(new Object(), CallKind.CHAT);

        assertThat(gates.analysisConcurrency(0)).isEqualTo(1);
    }
}
