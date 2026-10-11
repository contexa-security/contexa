package io.contexa.contexaiam.admin.promptquality.governance;

import org.springframework.jdbc.core.JdbcTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * The prompt version management tables as the OSS {@code db/schema.sql} defines them, for tests on an empty database:
 * the canonical DDL, not a copy of it.
 */
public final class PromptGovernanceTestSchema {

    private static final Pattern GOVERNANCE_DDL = Pattern.compile(
            "(?is)^create\\s+(unique\\s+)?(table|index)\\s+if\\s+not\\s+exists\\s+.*\\bprompt_governance_.*");

    private PromptGovernanceTestSchema() {
    }

    public static void apply(JdbcTemplate jdbcTemplate) {
        for (String statement : schema().split(";")) {
            String ddl = statement.lines()
                    .filter(line -> !line.strip().startsWith("--"))
                    .reduce("", (left, right) -> left + right + "\n")
                    .strip();
            if (GOVERNANCE_DDL.matcher(ddl).matches()) {
                jdbcTemplate.execute(ddl);
            }
        }
    }

    private static String schema() {
        try (InputStream stream = PromptGovernanceTestSchema.class.getResourceAsStream("/db/schema.sql")) {
            if (stream == null) {
                throw new IllegalStateException("db/schema.sql is not on the test classpath");
            }
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
