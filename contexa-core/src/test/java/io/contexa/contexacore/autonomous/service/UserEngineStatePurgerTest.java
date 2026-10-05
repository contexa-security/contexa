package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.store.InMemoryBaselineDataStore;
import io.contexa.contexacore.autonomous.blocking.InMemoryBlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.InMemoryZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.store.InMemoryBlockMfaStateStore;
import io.contexa.contexacore.autonomous.store.InMemorySecurityContextDataStore;
import org.junit.jupiter.api.Test;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class UserEngineStatePurgerTest {

    private static final String USER = "deleted-user";
    private static final String OTHER = "other-user";

    private final InMemoryZeroTrustActionRepository actions = new InMemoryZeroTrustActionRepository();
    private final InMemoryBlockingSignalBroadcaster broadcaster = new InMemoryBlockingSignalBroadcaster();
    private final InMemoryBlockMfaStateStore blockMfa = new InMemoryBlockMfaStateStore(actions);
    private final InMemoryBaselineDataStore baselines = new InMemoryBaselineDataStore();
    private final InMemorySecurityContextDataStore context = new InMemorySecurityContextDataStore();
    private final VectorStore vectorStore = mock(VectorStore.class);
    private final IForceLogoutService forceLogout = mock(IForceLogoutService.class);

    @Test
    void purgeRemovesTheStateThatANewAccountWithTheSameNameWouldInherit() {
        seed(USER);
        seed(OTHER);

        UserEngineStatePurgeResult result = purger(List.of()).purge(USER);

        assertThat(result.complete()).isTrue();
        assertThat(result.purgedSteps()).containsExactly("sessions", "decision-state", "blocking-signal",
                "block-mfa-state", "baseline", "security-context", "decision-history");
        assertThat(actions.getCurrentAction(USER, "any-context")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(broadcaster.isBlocked(USER)).isFalse();
        assertThat(blockMfa.isVerified(USER)).isFalse();
        assertThat(baselines.getUserBaseline(USER)).isNull();
        assertThat(context.isMfaVerified(USER)).isFalse();
        assertThat(context.getRecentWorkProfileObservations(null, USER, 10)).isEmpty();
        assertThat(context.getRecentWorkProfileObservations("tenant-a", USER, 10)).isEmpty();
        assertThat(context.getRecentPermissionChangeObservations("tenant-a", USER, 10)).isEmpty();
        assertThat(context.getAuthorizationScopeState("tenant-a", USER)).isNull();
        assertThat(context.getRecentLoginFailureCount(USER, null, 0L, Long.MAX_VALUE)).isZero();
        verify(forceLogout).forceLogoutByUserId(USER, "ACCOUNT_DELETED");
        Filter.Expression userFilter = new FilterExpressionBuilder().eq("userId", USER).build();
        verify(vectorStore).delete(userFilter);

        assertThat(actions.getCurrentAction(OTHER, "any-context")).isEqualTo(ZeroTrustAction.BLOCK);
        assertThat(broadcaster.isBlocked(OTHER)).isTrue();
        assertThat(baselines.getUserBaseline(OTHER)).isNotNull();
        assertThat(context.isMfaVerified(OTHER)).isTrue();
        assertThat(context.getRecentWorkProfileObservations("tenant-a", OTHER, 10)).isNotEmpty();
    }

    @Test
    void aFailingStepIsReportedAndTheOtherStepsStillRun() {
        seed(USER);
        UserStatePurgeContributor failing = new UserStatePurgeContributor() {
            @Override
            public String name() {
                return "host-records";
            }

            @Override
            public void purge(String userId) {
                throw new IllegalStateException("host store unavailable");
            }
        };

        UserEngineStatePurgeResult result = purger(List.of(failing)).purge(USER);

        assertThat(result.complete()).isFalse();
        assertThat(result.failedSteps()).containsOnlyKeys("host-records");
        assertThat(result.purgedSteps()).contains("decision-state", "baseline", "security-context");
        assertThat(actions.getCurrentAction(USER, "any-context")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    void aUserNameWithAnApostropheIsPurgedLikeAnyOther() {
        String quoted = "o'brien";
        seed(quoted);

        UserEngineStatePurgeResult result = purger(List.of()).purge(quoted);

        assertThat(result.complete()).isTrue();
        verify(vectorStore).delete(new FilterExpressionBuilder().eq("userId", quoted).build());
        assertThat(baselines.getUserBaseline(quoted)).isNull();
    }

    private UserEngineStatePurger purger(List<UserStatePurgeContributor> contributors) {
        return new UserEngineStatePurger(actions, broadcaster, blockMfa, baselines, context, null,
                vectorStore, forceLogout, contributors);
    }

    private void seed(String user) {
        actions.saveAction(user, ZeroTrustAction.ESCALATE, Map.of());
        actions.setBlockedFlag(user);
        broadcaster.registerBlock(user);
        blockMfa.setVerified(user);
        baselines.saveUserBaseline(user, BaselineVector.builder().userId(user).updateCount(25L).build());
        context.addWorkProfileObservation(null, user, "{\"path\":\"/documents\"}");
        context.addWorkProfileObservation("tenant-a", user, "{\"path\":\"/exports\"}");
        context.addPermissionChangeObservation("tenant-a", user, "{\"role\":\"ENGINEER\"}");
        context.setAuthorizationScopeState("tenant-a", user, "{\"scope\":\"engineering\"}");
        context.markMfaVerified(user);
        context.recordLoginFailure(user, "10.0.0.5", System.currentTimeMillis());
    }
}
