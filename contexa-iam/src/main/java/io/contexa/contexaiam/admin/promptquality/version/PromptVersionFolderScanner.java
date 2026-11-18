/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.admin.promptquality.version;

import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentException;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionProblem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The document folder (plan 3.8, 8): each node reads the folder the setting {@code contexa.prompt.versions.directory}
 * names at start and every minute. A document not registered yet, or one whose text changed, is saved as the next
 * version; the same document read again, or by another node, is the version it already is (the origin is unique). A
 * document that cannot be saved is not registered, and why is written to the scan record and logged as a warning.
 */
public class PromptVersionFolderScanner {

    private static final Logger log = LoggerFactory.getLogger(PromptVersionFolderScanner.class);

    /** The largest document the folder reads, in bytes. */
    static final long MAX_DOCUMENT_BYTES = 1_000_000L;

    /** What one reading of the folder found. */
    public record Scan(int documents, int registered, List<String> errors) {

        public Scan {
            errors = List.copyOf(errors);
        }
    }

    private final Supplier<JdbcTemplate> jdbc;
    private final PromptVersionService versions;
    private final Path folder;
    private final String node;
    private final Supplier<PromptAssembler.LengthLimit> limit;

    public PromptVersionFolderScanner(Supplier<JdbcTemplate> jdbc, PromptVersionService versions, Path folder,
                                      String node, Supplier<PromptAssembler.LengthLimit> limit) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.versions = Objects.requireNonNull(versions, "versions");
        this.folder = Objects.requireNonNull(folder, "folder");
        this.node = node != null && !node.isBlank() ? node : "node";
        this.limit = limit != null ? limit : () -> null;
    }

    /** Reads the folder once and records what it found. */
    public Scan scan() {
        List<String> errors = new ArrayList<>();
        int documents = 0;
        int registered = 0;
        if (!Files.isDirectory(folder)) {
            errors.add(folder + ": not a folder this node can read");
        }
        else {
            List<Path> files;
            try (Stream<Path> listed = Files.list(folder)) {
                files = listed.filter(Files::isRegularFile).filter(PromptVersionFolderScanner::isDocument).sorted()
                        .toList();
            }
            catch (IOException failure) {
                files = List.of();
                errors.add(folder + ": " + failure.getMessage());
            }
            for (Path file : files) {
                documents++;
                String name = file.getFileName().toString();
                try {
                    if (Files.size(file) > MAX_DOCUMENT_BYTES) {
                        throw new IOException("larger than " + MAX_DOCUMENT_BYTES + " bytes");
                    }
                    String text = Files.readString(file, StandardCharsets.UTF_8);
                    PromptVersionService.Saved saved = versions.create(PromptVersionService.PLATFORM_SCOPE, text,
                            PromptVersionRecord.FOLDER, name, PromptVersionAudit.FOLDER_ACTOR + node, limit.get());
                    if (saved.made()) {
                        registered++;
                    }
                }
                catch (PromptVersionDocumentException refused) {
                    errors.add(name + ": " + refused.problems().stream().map(PromptVersionFolderScanner::reason)
                            .collect(Collectors.joining(", ")));
                }
                catch (IOException | RuntimeException failure) {
                    errors.add(name + ": " + failure.getClass().getSimpleName() + ": " + failure.getMessage());
                }
            }
        }
        for (String error : errors) {
            log.warn("[PromptVersionFolder] a document is not registered: {}", error);
        }
        record(documents, registered, errors);
        return new Scan(documents, registered, errors);
    }

    private void record(int documents, int registered, List<String> errors) {
        try {
            jdbc.get().update("insert into ctxa_prompt_version_folder_scan (node_name, folder, scanned_at,"
                    + " document_count, registered_count, errors) values (?, ?, ?, ?, ?, ?)", node, folder.toString(),
                    Timestamp.from(versions.now()), documents, registered, errors.isEmpty() ? null
                            : String.join("\n", errors));
        }
        catch (RuntimeException failure) {
            log.error("[PromptVersionFolder] the scan of {} could not be recorded", folder, failure);
        }
    }

    private static boolean isDocument(Path file) {
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        return name.endsWith(".yaml") || name.endsWith(".yml");
    }

    private static String reason(PromptVersionProblem problem) {
        return problem.code() + (problem.where() != null ? " at " + problem.where() : "")
                + (problem.detail() != null ? " (" + problem.detail() + ")" : "");
    }
}
