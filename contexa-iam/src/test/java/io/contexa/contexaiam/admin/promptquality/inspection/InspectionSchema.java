package io.contexa.contexaiam.admin.promptquality.inspection;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The statements of the OSS schema the inspection store, queries and bundle trace read: the sealed package table with
 * its request facts shadow column, the safe JSON function, the inspection tables, the prompt release registry and the
 * two official verification tables that name sealed packages (R4-S5), taken
 * from {@code db/schema.sql} as is.
 */
final class InspectionSchema {

    private static final Pattern DOLLAR_TAG = Pattern.compile("\\$[A-Za-z_]*\\$");

    private InspectionSchema() {
    }

    static List<String> statements() {
        Set<String> wanted = new LinkedHashSet<>();
        for (String statement : split(read())) {
            String text = statement.replaceAll("(?m)^\\s*--.*$", "").trim();
            String lower = text.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
            if (lower.startsWith("create table if not exists sealed_evidence_package")
                    || lower.startsWith("create or replace function contexa_safe_jsonb")
                    || lower.equals("alter table sealed_evidence_package add column if not exists request_facts_jsonb jsonb")
                    || lower.contains("prompt_inspection_")
                    || lower.startsWith("create table if not exists prompt_governance_registry ")
                    || lower.startsWith("create unique index if not exists idx_prompt_governance_registry_identity")
                    || lower.startsWith("create table if not exists official_verification_run_batch ")
                    || lower.startsWith("create table if not exists verification_run_ledger ")
                    || lower.equals("alter table verification_run_ledger add column if not exists package_id varchar(160)")) {
                wanted.add(text);
            }
        }
        return new ArrayList<>(wanted);
    }

    /**
     * R4-S3: the sealed package table with its JSONB shadows, the safe JSON function, the shadows' backfill, indexes
     * and sync trigger, in schema order.
     */
    static List<String> sealedShadowStatements() {
        List<String> wanted = new ArrayList<>();
        for (String statement : split(read())) {
            String text = statement.replaceAll("(?m)^\\s*--.*$", "").trim();
            String lower = text.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
            if (lower.startsWith("create table if not exists sealed_evidence_package ")
                    || lower.startsWith("create or replace function contexa_safe_jsonb")
                    || lower.startsWith("create or replace function contexa_sync_sealed_evidence_jsonb")
                    || (lower.contains("sealed_evidence_package") && lower.contains("_jsonb"))) {
                wanted.add(text);
            }
        }
        return wanted;
    }

    private static String read() {
        try (InputStream input = InspectionSchema.class.getClassLoader().getResourceAsStream("db/schema.sql")) {
            if (input == null) {
                throw new IllegalStateException("db/schema.sql is not on the test class path");
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    /** Splits on semicolons outside line comments, single quotes and dollar-quoted bodies, as the OSS installer does. */
    private static List<String> split(String sql) {
        List<String> statements = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        String dollar = null;
        boolean quoted = false;
        for (int index = 0; index < sql.length(); index++) {
            char character = sql.charAt(index);
            if (dollar == null && !quoted && sql.startsWith("--", index)) {
                int end = sql.indexOf('\n', index);
                end = end < 0 ? sql.length() : end;
                current.append(sql, index, end);
                index = end - 1;
                continue;
            }
            if (dollar == null && !quoted && character == '$') {
                Matcher tag = DOLLAR_TAG.matcher(sql).region(index, sql.length());
                if (tag.lookingAt()) {
                    dollar = tag.group();
                    current.append(dollar);
                    index += dollar.length() - 1;
                    continue;
                }
            }
            else if (dollar != null && sql.startsWith(dollar, index)) {
                current.append(dollar);
                index += dollar.length() - 1;
                dollar = null;
                continue;
            }
            if (dollar == null && character == '\'') {
                quoted = !quoted;
            }
            if (dollar == null && !quoted && character == ';') {
                statements.add(current.toString());
                current.setLength(0);
                continue;
            }
            current.append(character);
        }
        if (!current.toString().isBlank()) {
            statements.add(current.toString());
        }
        return statements;
    }
}
