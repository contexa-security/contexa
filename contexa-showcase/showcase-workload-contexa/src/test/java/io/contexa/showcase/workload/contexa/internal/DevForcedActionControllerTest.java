package io.contexa.showcase.workload.contexa.internal;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The development-only forced decision accepts run principals and CHALLENGE or BLOCK only; a forced block goes the way
 * of the engine's own block, so its release can be checked.
 */
class DevForcedActionControllerTest {

    private final List<String> calls = new ArrayList<>();
    private final DevForcedActionController controller = new DevForcedActionController(recording(), recorder());

    @Test
    void aRunPrincipalTakesAForcedChallenge() {
        controller.force("v0123456789ab-eng-k", "CHALLENGE");

        assertThat(calls).containsExactly("saveAction v0123456789ab-eng-k=CHALLENGE");
    }

    @Test
    void aForcedBlockIsSavedFlaggedAndRecordedLikeTheEnginesOwn() {
        controller.force("v0123456789ab-eng-k", "BLOCK");

        assertThat(calls).containsExactly("saveAction v0123456789ab-eng-k=BLOCK",
                "setBlockedFlag v0123456789ab-eng-k",
                "recordBlock v0123456789ab-eng-k BLOCK " + DevForcedActionController.REASONING);
    }

    @Test
    void realAccountsAndOtherDecisionsAreRefused() {
        assertThatThrownBy(() -> controller.force("admin", "CHALLENGE")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> controller.force("admin", "BLOCK")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> controller.force("v0123456789ab-eng-k", "ALLOW"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> controller.force("v0123456789ab-eng-k", "ESCALATE"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(calls).isEmpty();
    }

    private ZeroTrustActionRepository recording() {
        return (ZeroTrustActionRepository) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{ZeroTrustActionRepository.class}, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "saveAction" -> calls.add("saveAction " + args[0] + "=" + ((ZeroTrustAction) args[1]).name());
                        case "setBlockedFlag" -> calls.add("setBlockedFlag " + args[0]);
                        default -> throw new UnsupportedOperationException(method.getName());
                    }
                    return null;
                });
    }

    private ObjectProvider<IBlockedUserRecorder> recorder() {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("blockedUsers", Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{IBlockedUserRecorder.class}, (proxy, method, args) -> {
                    if ("recordBlock".equals(method.getName())) {
                        calls.add("recordBlock " + args[1] + " " + args[3] + " " + args[4]);
                        return null;
                    }
                    throw new UnsupportedOperationException(method.getName());
                }));
        return beans.getBeanProvider(IBlockedUserRecorder.class);
    }
}
