package io.contexa.contexaiam.admin.promptquality.inspection;

import org.springframework.jdbc.core.JdbcOperations;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** The releases of the {@code prompt_governance_registry} table of the OSS schema. */
public class JdbcPromptReleaseLookup implements PromptReleaseLookup {

    private final JdbcOperations jdbc;

    public JdbcPromptReleaseLookup(JdbcOperations jdbc) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
    }

    @Override
    public Optional<PromptRelease> find(String registryScope, String promptKey, String templateKey,
                                        String promptVersion) {
        List<PromptRelease> releases = jdbc.query("""
                        select prompt_version, contract_version, prompt_artifact_hash_sha256, release_approval_reference,
                               release_status
                          from prompt_governance_registry
                         where registry_scope = ?
                           and prompt_key = ?
                           and template_key = ?
                           and prompt_version = ?
                        """, (rs, rowNum) -> new PromptRelease(rs.getString("prompt_version"),
                        rs.getString("contract_version"), rs.getString("prompt_artifact_hash_sha256"),
                        rs.getString("release_approval_reference"), rs.getString("release_status")),
                registryScope, promptKey, templateKey, promptVersion);
        return releases.stream().findFirst();
    }
}
