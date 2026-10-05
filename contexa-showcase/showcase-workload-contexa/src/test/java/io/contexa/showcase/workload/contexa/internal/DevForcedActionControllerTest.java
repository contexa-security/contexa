package io.contexa.showcase.workload.contexa.internal;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The development-only forced decision accepts run principals and CHALLENGE only. */
class DevForcedActionControllerTest {

    private final List<String> saved = new ArrayList<>();
    private final DevForcedActionController controller = new DevForcedActionController(recording());

    @Test
    void aRunPrincipalTakesAForcedChallenge() {
        controller.force("v0123456789ab-eng-k", "CHALLENGE");

        assertThat(saved).containsExactly("v0123456789ab-eng-k=CHALLENGE");
    }

    @Test
    void realAccountsAndOtherDecisionsAreRefused() {
        assertThatThrownBy(() -> controller.force("admin", "CHALLENGE")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> controller.force("v0123456789ab-eng-k", "BLOCK"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> controller.force("v0123456789ab-eng-k", "ALLOW"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(saved).isEmpty();
    }

    private ZeroTrustActionRepository recording() {
        return (ZeroTrustActionRepository) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{ZeroTrustActionRepository.class}, (proxy, method, args) -> {
                    if ("saveAction".equals(method.getName())) {
                        saved.add(args[0] + "=" + ((ZeroTrustAction) args[1]).name());
                        return null;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }
}
