package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository.ZeroTrustAnalysisData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryZeroTrustActionRepositoryTest {

    private InMemoryZeroTrustActionRepository repository;

    @BeforeEach
    void setUp() {
        repository = new InMemoryZeroTrustActionRepository();
    }

    @Test
    @DisplayName("saveAction stores action and getCurrentAction retrieves it")
    void saveAction_thenGetCurrentAction_returnsStoredAction() {
        repository.saveAction("user1", ZeroTrustAction.ALLOW, null);

        ZeroTrustAction result = repository.getCurrentAction("user1");

        assertThat(result).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("getCurrentAction returns PENDING_ANALYSIS for unknown user")
    void getCurrentAction_unknownUser_returnsPendingAnalysis() {
        ZeroTrustAction result = repository.getCurrentAction("unknown");

        assertThat(result).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("getCurrentAction returns PENDING_ANALYSIS for null userId")
    void getCurrentAction_nullUserId_returnsPendingAnalysis() {
        ZeroTrustAction result = repository.getCurrentAction(null);

        assertThat(result).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("Context binding hash mismatch returns PENDING_ANALYSIS")
    void getCurrentAction_contextBindingHashMismatch_returnsPendingAnalysis() {
        Map<String, Object> fields = Map.of("contextBindingHash", "hash-abc");
        repository.saveAction("user1", ZeroTrustAction.ALLOW, fields);

        ZeroTrustAction result = repository.getCurrentAction("user1", "hash-different");

        assertThat(result).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    @Test
    @DisplayName("Context binding hash match returns original action")
    void getCurrentAction_contextBindingHashMatch_returnsOriginalAction() {
        Map<String, Object> fields = Map.of("contextBindingHash", "hash-abc");
        repository.saveAction("user1", ZeroTrustAction.ALLOW, fields);

        ZeroTrustAction result = repository.getCurrentAction("user1", "hash-abc");

        assertThat(result).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("incrementBlockMfaFailCount atomically increments counter")
    void incrementBlockMfaFailCount_incrementsAtomically() {
        long first = repository.incrementBlockMfaFailCount("user1");
        long second = repository.incrementBlockMfaFailCount("user1");
        long third = repository.incrementBlockMfaFailCount("user1");

        assertThat(first).isEqualTo(1);
        assertThat(second).isEqualTo(2);
        assertThat(third).isEqualTo(3);
        assertThat(repository.getBlockMfaFailCount("user1")).isEqualTo(3);
    }

    @Test
    @DisplayName("incrementBlockMfaFailCount returns 0 for null userId")
    void incrementBlockMfaFailCount_nullUserId_returnsZero() {
        long result = repository.incrementBlockMfaFailCount(null);

        assertThat(result).isZero();
    }

    @Test
    @DisplayName("approveOverrideAtomically removes BLOCK and sets new action")
    void approveOverrideAtomically_removesBlockAndSetsNewAction() {
        repository.setBlockedFlag("user1");
        assertThat(repository.getCurrentAction("user1")).isEqualTo(ZeroTrustAction.BLOCK);

        repository.approveOverrideAtomically("user1", ZeroTrustAction.ALLOW);

        assertThat(repository.getCurrentAction("user1")).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("setBlockedFlag causes getCurrentAction to return BLOCK")
    void setBlockedFlag_getCurrentAction_returnsBlock() {
        repository.saveAction("user1", ZeroTrustAction.ALLOW, null);
        repository.setBlockedFlag("user1");

        ZeroTrustAction result = repository.getCurrentAction("user1");

        assertThat(result).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("removeBlockedFlag restores previous action")
    void removeBlockedFlag_restoresPreviousAction() {
        repository.saveAction("user1", ZeroTrustAction.ALLOW, null);
        repository.setBlockedFlag("user1");
        repository.removeBlockedFlag("user1");

        ZeroTrustAction result = repository.getCurrentAction("user1");

        assertThat(result).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("saveAction tracks previous action")
    void saveAction_tracksPreviousAction() {
        repository.saveAction("user1", ZeroTrustAction.ALLOW, null);
        repository.saveAction("user1", ZeroTrustAction.CHALLENGE, null);

        ZeroTrustAction previous = repository.getPreviousActionFromHash("user1");

        assertThat(previous).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("saveAction with additionalFields stores riskScore and confidence")
    void saveAction_withAdditionalFields_storesAnalysisData() {
        Map<String, Object> fields = Map.of(
                "riskScore", 0.85,
                "confidence", 0.92,
                "threatEvidence", "suspicious-ip",
                "analysisDepth", 3
        );

        repository.saveAction("user1", ZeroTrustAction.CHALLENGE, fields);

        ZeroTrustAnalysisData data = repository.getAnalysisData("user1");
        assertThat(data.action()).isEqualTo("CHALLENGE");
        assertThat(data.riskScore()).isEqualTo(0.85);
        assertThat(data.confidence()).isEqualTo(0.92);
        assertThat(data.threatEvidence()).isEqualTo("suspicious-ip");
        assertThat(data.analysisDepth()).isEqualTo(3);
    }

    @Test
    @DisplayName("getAnalysisData returns pending for null userId")
    void getAnalysisData_nullUserId_returnsPending() {
        ZeroTrustAnalysisData data = repository.getAnalysisData(null);

        assertThat(data).isNotNull();
    }

    @Test
    @DisplayName("saveActionWithPrevious preserves existing analysis data")
    void saveActionWithPrevious_preservesExistingAnalysisData() {
        Map<String, Object> fields = Map.of("riskScore", 0.5, "confidence", 0.8);
        repository.saveAction("user1", ZeroTrustAction.ALLOW, fields);

        repository.saveActionWithPrevious("user1", ZeroTrustAction.CHALLENGE);

        ZeroTrustAction current = repository.getActionFromHash("user1");
        ZeroTrustAction previous = repository.getPreviousActionFromHash("user1");
        assertThat(current).isEqualTo(ZeroTrustAction.CHALLENGE);
        assertThat(previous).isEqualTo(ZeroTrustAction.ALLOW);
    }

    @Test
    @DisplayName("removeAllUserData clears all user-related data")
    void removeAllUserData_clearsAllData() {
        repository.saveAction("user1", ZeroTrustAction.ALLOW, null);
        repository.setBlockedFlag("user1");
        repository.incrementBlockMfaFailCount("user1");

        repository.removeAllUserData("user1");

        assertThat(repository.getCurrentAction("user1")).isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
        assertThat(repository.getBlockMfaFailCount("user1")).isZero();
    }

    @Test
    @DisplayName("BLOCK action saves to lastVerifiedStore for audit tracking")
    void saveAction_blockAction_savesToLastVerified() {
        repository.saveAction("user1", ZeroTrustAction.BLOCK, null);

        ZeroTrustAction lastVerified = repository.getLastVerifiedAction("user1");

        assertThat(lastVerified).isEqualTo(ZeroTrustAction.BLOCK);
    }

    @Test
    @DisplayName("ALLOW action saves to lastVerifiedStore")
    void saveAction_allowAction_savesToLastVerified() {
        repository.saveAction("user1", ZeroTrustAction.ALLOW, null);

        ZeroTrustAction lastVerified = repository.getLastVerifiedAction("user1");

        assertThat(lastVerified).isEqualTo(ZeroTrustAction.ALLOW);
    }
}
