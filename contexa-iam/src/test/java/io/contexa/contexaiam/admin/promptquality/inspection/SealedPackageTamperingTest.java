package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.verification.evidence.HmacEvidenceSigner;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity.Status;
import io.contexa.contexaiam.admin.promptquality.evidence.JdbcSealedEvidencePackageRepository;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Q-21 (PR-75, PR-76): someone who holds the database and the code, but not the signing key, changes a sealed package,
 * as measurement M14 does (cases T1 to T9). Each case seals packages through the store and changes the rows on
 * PostgreSQL, with the schema's own trigger in place; the verdict is the store's integrity read back.
 */
class SealedPackageTamperingTest {

    private static final String TABLE = "ctxa_sealed_evidence_package";
    private static final String TO_BLOCK = "decision_json = replace(decision_json, '\"action\":\"ALLOW\"', "
            + "'\"action\":\"BLOCK\"')";
    private static final Duration KEPT_AT_LEAST = Duration.ofDays(30);

    private PostgresTestDatabase database;
    private JdbcTemplate jdbc;
    private JdbcSealedEvidencePackageRepository store;
    private SealedEvidencePackageIntegrity integrity;

    @BeforeEach
    void setUp() {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        InspectionSchema.sealedLinkedStatements().forEach(jdbc::execute);
        integrity = new SealedEvidencePackageIntegrity(HmacEvidenceSigner.of(Map.of("k1", Base64.getEncoder()
                .encodeToString("k1-0123456789abcdef0123456789abcd".getBytes())), null));
        store = new JdbcSealedEvidencePackageRepository(jdbc);
        store.setIntegrity(integrity);
        integrity.setChain(store, KEPT_AT_LEAST, Clock.systemUTC());
    }

    @AfterEach
    void tearDown() {
        database.close();
    }

    @Test
    void packagesAsTheyWereSealedAreVerified() {
        List<String> ids = sealed(4);

        assertThat(ids).allSatisfy(id -> assertThat(status(id)).isEqualTo(Status.VERIFIED));
    }

    @Test
    void t1AChangedDecisionFails() {
        String id = sealed(3).get(1);

        change(id, TO_BLOCK);

        assertThat(status(id)).isEqualTo(Status.MISMATCH);
    }

    @Test
    void t2AChangedPromptFails() {
        String id = sealed(3).get(1);

        change(id, "user_prompt_text = user_prompt_text || ' changed'");

        assertThat(status(id)).isEqualTo(Status.MISMATCH);
    }

    @Test
    void t3AChangedDecisionWithItsHashComputedAgainFails() {
        String id = sealed(3).get(1);

        change(id, TO_BLOCK);
        rehash(id, 3);

        assertThat(status(id)).isEqualTo(Status.MISMATCH);
    }

    @Test
    void t4ARemovedSignatureFails() {
        String id = sealed(3).get(1);

        change(id, TO_BLOCK + ", package_signature = null, signature_key_id = null");
        rehash(id, 3);

        assertThat(status(id)).isEqualTo(Status.MISMATCH);
    }

    @Test
    void t5ASchemaLoweredToTwoFails() {
        String id = sealed(3).get(1);

        change(id, TO_BLOCK + ", schema_version = 2, package_signature = null, signature_key_id = null");
        rehash(id, 2);

        assertThat(status(id)).isEqualTo(Status.MISMATCH);
    }

    @Test
    void t6ASchemaLoweredToOneFails() {
        String id = sealed(3).get(1);

        change(id, TO_BLOCK + ", schema_version = 1, package_signature = null, signature_key_id = null");
        rehash(id, 1);

        assertThat(status(id)).isEqualTo(Status.MISMATCH);
    }

    @Test
    void t7AnotherOwnerFails() {
        String id = sealed(3).get(1);

        change(id, "user_id = 'someone-else'");
        rehash(id, 3);

        assertThat(status(id)).isEqualTo(Status.MISMATCH);
    }

    /**
     * A package made to read as older than the first signature leaves the one sealed after it naming a hash no package
     * has: the lowered package itself reads as an old one, the break shows on the next.
     */
    @Test
    void aPackageBackdatedBeforeTheFirstSignatureBreaksTheLinkOfTheNext() {
        List<String> ids = sealed(3);

        change(ids.get(1), TO_BLOCK + ", schema_version = 2, package_signature = null, signature_key_id = null, "
                + "captured_at = captured_at - interval '1 year'");
        rehash(ids.get(1), 2);

        assertThat(status(ids.get(2))).isEqualTo(Status.MISMATCH);
    }

    @Test
    void aFirstPackageLoweredBreaksTheLinkOfTheNext() {
        List<String> ids = sealed(3);

        change(ids.get(0), TO_BLOCK + ", schema_version = 2, package_signature = null, signature_key_id = null");
        rehash(ids.get(0), 2);

        assertThat(status(ids.get(1))).isEqualTo(Status.MISMATCH);
    }

    @Test
    void t9TheNextAfterARemovedPackageFails() {
        List<String> ids = sealed(4);

        jdbc.update("delete from " + TABLE + " where package_id = ?", ids.get(2));

        assertThat(status(ids.get(3))).isEqualTo(Status.MISMATCH);
        assertThat(status(ids.get(1))).as("the ones before it stand").isEqualTo(Status.VERIFIED);
    }

    /** Known limit: nothing names the last package, so removing it cannot show; a later package links to the one before. */
    @Test
    void theLastPackageRemovedDoesNotShow() {
        List<String> ids = sealed(3);

        jdbc.update("delete from " + TABLE + " where package_id = ?", ids.get(2));

        assertThat(status(ids.get(1))).isEqualTo(Status.VERIFIED);
        assertThat(status(sealOne(9))).isEqualTo(Status.VERIFIED);
    }

    @Test
    void theRetentionRemovingOldCleanPackagesBreaksNoLink() {
        List<String> ids = sealed(4);
        jdbc.update("update " + TABLE + " set captured_at = captured_at - interval '40 days' where package_id = ?",
                ids.get(0));
        jdbc.update("update " + TABLE + " set captured_at = captured_at - interval '39 days' where package_id = ?",
                ids.get(1));

        jdbc.update("delete from " + TABLE + " where package_id = ?", ids.get(1));

        assertThat(store.previousKept(read(ids.get(2)))).isFalse();
        assertThat(status(ids.get(2))).isEqualTo(Status.VERIFIED);
    }

    /**
     * T8. The schema's trigger writes the copy back from the sealed column on every update, so measurement M14's update
     * of the copy changes nothing; a copy changed with the trigger off is not what the counts read.
     */
    @Test
    void t8TheCountsReadTheSealedDecisionAndNotItsCopy() {
        InspectionSchema.statements().forEach(jdbc::execute);
        JdbcPromptInspectionQueries queries = new JdbcPromptInspectionQueries(jdbc);
        String id = sealOne(0);
        jdbc.update("update " + TABLE + " set prompt_execution_metadata_json = ? where package_id = ?",
                "{\"" + PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR + "\":{\"promptBundleVersion\":\"b1\"}}", id);
        String toBlock = "decision_jsonb = jsonb_set(decision_jsonb, '{action}', '\"BLOCK\"')";

        change(id, toBlock);
        assertThat(copiedAction(id)).as("written back by the trigger").isEqualTo("ALLOW");

        jdbc.execute("alter table " + TABLE + " disable trigger user");
        change(id, toBlock);
        jdbc.execute("alter table " + TABLE + " enable trigger user");

        assertThat(copiedAction(id)).isEqualTo("BLOCK");
        Instant now = Instant.now();
        assertThat(queries.bundleOutcomes(now.minus(Duration.ofHours(1)), now.plus(Duration.ofHours(1)), List.of("b1")))
                .singleElement().satisfies(outcome -> assertThat(outcome.action()).isEqualTo("ALLOW"));
    }

    private String copiedAction(String packageId) {
        return jdbc.queryForObject("select decision_jsonb ->> 'action' from " + TABLE + " where package_id = ?",
                String.class, packageId);
    }

    @Test
    void packagesCapturedBeforeTheKeyStayVerifiedAndTheOnesAfterItDoNot() {
        Instant past = Instant.now().minus(Duration.ofDays(3)).truncatedTo(ChronoUnit.MICROS);
        SealedEvidencePackageIntegrity withoutKey = new SealedEvidencePackageIntegrity();
        SealedEvidencePackage older = pkg("before-the-key", past);
        older.setSchemaVersion(2);
        older.setPackageHash(withoutKey.computeHash(older));
        store.save(older);
        List<String> ids = sealed(2);

        assertThat(status("before-the-key")).isEqualTo(Status.VERIFIED);
        change(ids.get(1), "schema_version = 2, package_signature = null, signature_key_id = null");
        rehash(ids.get(1), 2);
        assertThat(status(ids.get(1))).isEqualTo(Status.MISMATCH);
    }

    private Status status(String packageId) {
        return integrity.evaluate(read(packageId));
    }

    private SealedEvidencePackage read(String packageId) {
        return store.findByPackageId(packageId).orElseThrow();
    }

    private List<String> sealed(int packages) {
        List<String> ids = new ArrayList<>();
        for (int turn = 0; turn < packages; turn++) {
            ids.add(sealOne(turn));
        }
        return ids;
    }

    private String sealOne(int turn) {
        String id = "pkg-" + turn;
        SealedEvidencePackage pkg = pkg(id, Instant.now().truncatedTo(ChronoUnit.MICROS));
        pkg.setSchemaVersion(SealedEvidencePackageIntegrity.LINKED_SCHEMA_VERSION);
        store.save(pkg);
        return id;
    }

    private static SealedEvidencePackage pkg(String packageId, Instant capturedAt) {
        return SealedEvidencePackage.builder()
                .packageId(packageId)
                .correlationId("request-" + packageId)
                .userId("alice")
                .capturedAt(capturedAt)
                .userPromptText("prompt")
                .userPromptHash("sha256:prompt")
                .decisionJson("{\"action\":\"ALLOW\"}")
                .build();
    }

    private void change(String packageId, String assignments) {
        jdbc.update("update " + TABLE + " set " + assignments + " where package_id = ?", packageId);
    }

    /** The hash as anyone holding the code computes it, under the schema the row now says. */
    private void rehash(String packageId, int schema) {
        SealedEvidencePackage row = read(packageId);
        row.setSchemaVersion(schema);
        jdbc.update("update " + TABLE + " set package_hash = ? where package_id = ?", integrity.computeHash(row),
                packageId);
    }
}
