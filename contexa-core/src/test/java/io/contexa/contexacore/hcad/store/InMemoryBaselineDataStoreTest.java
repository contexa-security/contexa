package io.contexa.contexacore.hcad.store;

import io.contexa.contexacommon.hcad.domain.BaselineVector;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryBaselineDataStoreTest {

    private InMemoryBaselineDataStore store;

    @BeforeEach
    void setUp() {
        store = new InMemoryBaselineDataStore();
    }

    @Test
    @DisplayName("Save and retrieve user baseline")
    void saveUserBaseline_getUserBaseline_returnsBaseline() {
        BaselineVector baseline = BaselineVector.builder()
                .userId("user1")
                .normalIpRanges(new String[]{"192.168.1.0/24"})
                .normalAccessHours(new Integer[]{9, 10, 11, 12, 13, 14, 15, 16, 17})
                .lastUpdated(Instant.now())
                .build();

        store.saveUserBaseline("user1", baseline);

        BaselineVector result = store.getUserBaseline("user1");
        assertThat(result).isNotNull();
        assertThat(result.getUserId()).isEqualTo("user1");
        assertThat(result.getNormalIpRanges()).containsExactly("192.168.1.0/24");
    }

    @Test
    @DisplayName("getUserBaseline returns null for unknown user")
    void getUserBaseline_unknownUser_returnsNull() {
        BaselineVector result = store.getUserBaseline("unknown");

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("getUserBaseline throws NullPointerException for null userId")
    void getUserBaseline_nullUserId_throwsNpe() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> store.getUserBaseline(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("saveUserBaseline overwrites existing baseline")
    void saveUserBaseline_overwritesExisting() {
        BaselineVector first = BaselineVector.builder()
                .userId("user1")
                .avgTrustScore(0.5)
                .build();
        BaselineVector second = BaselineVector.builder()
                .userId("user1")
                .avgTrustScore(0.9)
                .build();

        store.saveUserBaseline("user1", first);
        store.saveUserBaseline("user1", second);

        BaselineVector result = store.getUserBaseline("user1");
        assertThat(result.getAvgTrustScore()).isEqualTo(0.9);
    }

    @Test
    @DisplayName("Save and retrieve organization baseline")
    void saveOrganizationBaseline_getOrganizationBaseline_returnsBaseline() {
        BaselineVector baseline = BaselineVector.builder()
                .normalIpRanges(new String[]{"10.0.0.0/8"})
                .avgRequestCount(1000L)
                .lastUpdated(Instant.now())
                .build();

        store.saveOrganizationBaseline("org1", baseline);

        BaselineVector result = store.getOrganizationBaseline("org1");
        assertThat(result).isNotNull();
        assertThat(result.getNormalIpRanges()).containsExactly("10.0.0.0/8");
        assertThat(result.getAvgRequestCount()).isEqualTo(1000L);
    }

    @Test
    @DisplayName("getOrganizationBaseline returns null for unknown org")
    void getOrganizationBaseline_unknownOrg_returnsNull() {
        BaselineVector result = store.getOrganizationBaseline("unknown-org");

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("User and organization baselines are independent")
    void userAndOrgBaselines_areIndependent() {
        BaselineVector userBaseline = BaselineVector.builder()
                .userId("user1")
                .avgTrustScore(0.7)
                .build();
        BaselineVector orgBaseline = BaselineVector.builder()
                .avgTrustScore(0.9)
                .build();

        store.saveUserBaseline("id1", userBaseline);
        store.saveOrganizationBaseline("id1", orgBaseline);

        assertThat(store.getUserBaseline("id1").getAvgTrustScore()).isEqualTo(0.7);
        assertThat(store.getOrganizationBaseline("id1").getAvgTrustScore()).isEqualTo(0.9);
    }
}
