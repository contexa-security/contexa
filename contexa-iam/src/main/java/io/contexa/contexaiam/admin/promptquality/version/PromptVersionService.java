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

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptRelease;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocument;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentException;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentReader;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentWriter;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionNames;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionProblem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * The versions of the prompts in the database (plan 3.3, 3.6, 3.7): the product documents a build ships registered as
 * Contexa versions, an organization's documents from the screen, an import or the document folder registered as its
 * versions, every one checked before it is saved, numbered by a count per scope and prompt and never changed after.
 * A version is found by its number, assembled from its chain of bases once and kept for good.
 */
public class PromptVersionService {

    private static final Logger log = LoggerFactory.getLogger(PromptVersionService.class);

    /** The scope of the platform, as the registry names it. */
    public static final String PLATFORM_SCOPE = "PLATFORM_GLOBAL";
    /** How many times a save takes the next number again when another save took it first. */
    private static final int NUMBER_ATTEMPTS = 8;
    private static final String ORIGIN_INDEX = "ctxa_idx_prompt_version_origin";

    /**
     * What the registry row of a prompt's versions names (the template that runs it), so the release machinery that
     * reads the registry reads a version as a release.
     */
    public record RegistryTarget(String templateKey, String contractVersion, String templateClassName, String owner) {
    }

    /** A saved version: its number and name, its content hash, and whether this save made it or found it made. */
    public record Saved(int number, String name, String contentHash, boolean made) {
    }

    private final Supplier<JdbcTemplate> jdbc;
    private final List<ProductPromptRelease> products;
    private final Map<String, RegistryTarget> targets;
    private final PromptVersionAudit audit;
    private final Clock clock;
    private final PromptVersionDocumentReader reader = new PromptVersionDocumentReader();
    private final PromptVersionDocumentWriter writer = new PromptVersionDocumentWriter();
    private final PromptAssembler assembler = new PromptAssembler();
    /** The assembled versions, by scope, prompt and number: a version does not change, so it is kept for good. */
    private final Map<String, AssembledPrompt> assembled = new ConcurrentHashMap<>();

    public PromptVersionService(Supplier<JdbcTemplate> jdbc, List<ProductPromptRelease> products,
                                Map<String, RegistryTarget> targets, PromptVersionAudit audit, Clock clock) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.products = List.copyOf(products);
        this.targets = Map.copyOf(targets);
        this.audit = audit != null ? audit : PromptVersionAudit.none();
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    /**
     * Registers the product documents (plan 3.3): a first installation registers the newest release of each prompt as
     * its first version; an upgrade registers each release newer than the newest one registered, in order. The
     * version a decision uses does not change: the label stays where it was. Returns the versions this call made.
     */
    public List<Saved> registerProducts(String scope) {
        List<Saved> made = new ArrayList<>();
        Map<String, List<ProductPromptRelease>> byPrompt = new LinkedHashMap<>();
        products.forEach(release -> byPrompt.computeIfAbsent(release.prompt(), key -> new ArrayList<>()).add(release));
        for (Map.Entry<String, List<ProductPromptRelease>> prompt : byPrompt.entrySet()) {
            List<ProductPromptRelease> releases = prompt.getValue();
            List<String> registered = jdbc.get().queryForList("select origin_name from ctxa_prompt_version where"
                    + " registry_scope = ? and prompt_key = ? and origin = ?", String.class, scopeOf(scope),
                    prompt.getKey(), PromptVersionRecord.PRODUCT);
            int newest = -1;
            for (int index = 0; index < releases.size(); index++) {
                if (registered.contains(releases.get(index).release())) {
                    newest = index;
                }
            }
            List<ProductPromptRelease> toRegister = newest < 0 ? List.of(releases.get(releases.size() - 1))
                    : releases.subList(newest + 1, releases.size());
            for (ProductPromptRelease release : toRegister) {
                Saved saved = registerProduct(scopeOf(scope), release);
                if (saved.made()) {
                    made.add(saved);
                }
            }
        }
        return made;
    }

    /**
     * The move of an installation that ran bundles (plan 6-3, 7): the registry rows of a prompt that name a bundle, not
     * a version, are retired, so no label or canary names a bundle the build no longer runs. They are kept: the trace of
     * earlier sealed decisions reads them. Returns how many rows were retired; a second run retires none.
     */
    public int retireEarlierBundles(String scope) {
        int retired = 0;
        for (String prompt : products.stream().map(ProductPromptRelease::prompt).distinct().toList()) {
            List<String> rows = jdbc.get().queryForList("select prompt_version from ctxa_prompt_governance_registry where"
                    + " registry_scope = ? and prompt_key = ? and release_status <> ?", String.class, scopeOf(scope),
                    prompt, PromptBundleState.RETIRED.name());
            for (String version : rows) {
                if (PromptVersionNames.number(version).isPresent()) {
                    continue;
                }
                retired += jdbc.get().update("update ctxa_prompt_governance_registry set release_status = ?,"
                        + " updated_at = ? where registry_scope = ? and prompt_key = ? and prompt_version = ?",
                        PromptBundleState.RETIRED.name(), Timestamp.from(clock.instant()), scopeOf(scope), prompt,
                        version);
            }
        }
        if (retired > 0) {
            log.info("[PromptVersion] {} registry rows of earlier bundles were retired; the versions run", retired);
        }
        return retired;
    }

    private Saved registerProduct(String scope, ProductPromptRelease release) {
        PromptVersionDocument document = reader.read(release.document());
        AssembledPrompt version = assembler.product(document);
        return save(scope, release.prompt(), document, release.document(), version, null, null,
                PromptVersionRecord.CONTEXA, PromptVersionRecord.PRODUCT, release.release(), "contexa");
    }

    /**
     * Saves an organization's document as the next version (plan 3.5, 3.6): its base is the version with the content
     * hash it names, else the version its number names; it is checked against that base, and refused with every
     * problem when it has one. A document from the folder or an import that is already registered is found, not saved
     * again.
     *
     * @param origin     SCREEN, IMPORT or FOLDER
     * @param originName the document's file name; null for a screen save, which gets a name of its own
     */
    public Saved create(String scope, String yaml, String origin, String originName, String createdBy,
                        PromptAssembler.LengthLimit limit) {
        String scopeName = scopeOf(scope);
        PromptVersionDocument document = reader.read(yaml);
        if (originName != null && !originName.isBlank()) {
            // The folder reads its documents every minute: one registered already is found before it is checked again.
            Optional<PromptVersionRecord> registered = byOrigin(scopeName, document.prompt(), origin, originName.trim(),
                    PromptBundleHashes.sha256Hex(yaml.replace("\r\n", "\n")));
            if (registered.isPresent()) {
                return new Saved(registered.get().number(), registered.get().name(), registered.get().contentHash(),
                        false);
            }
        }
        Checked checked = checked(scopeName, document, origin, limit);
        if (!checked.problems().isEmpty()) {
            throw new PromptVersionDocumentException(checked.problems());
        }
        AssembledPrompt version = assembler.apply(checked.base(), document);
        String name = originName != null && !originName.isBlank() ? originName.trim()
                : "screen:" + UUID.randomUUID();
        Saved saved = save(scopeName, document.prompt(), document, yaml, version, checked.record().number(),
                checked.base().contentHash(), PromptVersionRecord.ORGANIZATION, origin, name, createdBy);
        if (saved.made() && PromptVersionRecord.FOLDER.equals(origin)) {
            audit.record(PromptVersionAudit.FOLDER_REGISTERED, scopeName, document.prompt(), saved.name(), createdBy,
                    name);
        }
        return saved;
    }

    /**
     * What the checks before saving find in an organization's document (plan 3.5): every problem, none when it can be
     * saved, with the estimated system prompt tokens of its base and of the version it would make. A document that
     * cannot be read, a rendered copy or one whose base this server does not have is refused at once.
     *
     * @param origin SCREEN for a version made on the screen (its base cannot have come from a document)
     */
    public Preview check(String scope, String yaml, String origin, PromptAssembler.LengthLimit limit) {
        PromptVersionDocument document = reader.read(yaml);
        Checked checked = checked(scopeOf(scope), document, origin, limit);
        return new Preview(checked.record(), checked.problems(), checked.check().baseSystemTokens(),
                checked.check().systemTokens());
    }

    /** What a check found: the base version, the problems, and the system prompt tokens of the base and the version. */
    public record Preview(PromptVersionRecord base, List<PromptVersionProblem> problems, int baseSystemTokens,
                          int systemTokens) {

        public Preview {
            problems = List.copyOf(problems);
        }
    }

    private record Checked(PromptVersionRecord record, AssembledPrompt base, PromptAssembler.Check check,
                           List<PromptVersionProblem> problems) {
    }

    private Checked checked(String scopeName, PromptVersionDocument document, String origin,
                            PromptAssembler.LengthLimit limit) {
        List<PromptVersionProblem> problems = new ArrayList<>();
        if (document.kind() == PromptVersionDocument.Kind.RENDERED) {
            throw new PromptVersionDocumentException(List.of(new PromptVersionProblem(
                    PromptVersionProblem.Code.RENDERED_DOCUMENT, "kind", null)));
        }
        Optional<PromptVersionRecord> base = base(scopeName, document);
        if (base.isEmpty()) {
            throw new PromptVersionDocumentException(List.of(new PromptVersionProblem(PromptVersionProblem.Code.NO_BASE,
                    "basedOn", document.basedOnHash() != null ? document.basedOnHash() : document.basedOn())));
        }
        if (PromptVersionRecord.SCREEN.equals(origin) && base.get().fromDocument()) {
            problems.add(new PromptVersionProblem(PromptVersionProblem.Code.BASE_FROM_DOCUMENT, "basedOn",
                    base.get().name()));
        }
        AssembledPrompt baseVersion = assembled(scopeName, base.get().prompt(), base.get().number())
                .orElseThrow(() -> new IllegalStateException("The base version " + base.get().name()
                        + " cannot be assembled"));
        // The length limit is the decision model's context with the longest recent decision input (plan 3.5, check 4);
        // another prompt has no such limit to check against (plan 3.11).
        PromptAssembler.Check check = assembler.check(baseVersion, document,
                SecurityDecisionPromptDocument.PROMPT.equals(base.get().prompt()) ? limit : null);
        problems.addAll(check.problems());
        return new Checked(base.get(), baseVersion, check, problems);
    }

    /** The prompts the build ships product documents for, in the order of the build's list. */
    public List<String> prompts() {
        return products.stream().map(ProductPromptRelease::prompt).distinct().toList();
    }

    /** What the registry row of the prompt's versions names (the template that runs them); empty without one. */
    public Optional<RegistryTarget> target(String prompt) {
        return Optional.ofNullable(prompt != null ? targets.get(prompt) : null);
    }

    /** The base an organization's document names: by its content hash first, then by its number. */
    private Optional<PromptVersionRecord> base(String scope, PromptVersionDocument document) {
        String hash = document.basedOnHash() != null ? document.basedOnHash().trim().replaceFirst("^sha256:", "") : null;
        if (hash != null && !hash.isBlank()) {
            List<PromptVersionRecord> byHash = jdbc.get().query("select * from ctxa_prompt_version where registry_scope"
                    + " = ? and prompt_key = ? and content_hash = ? order by version_number", ROW, scope,
                    document.prompt(), hash);
            if (!byHash.isEmpty()) {
                return Optional.of(byHash.get(0));
            }
            if (document.basedOn() == null) {
                return Optional.empty();
            }
        }
        OptionalInt number = PromptVersionNames.number(document.basedOn());
        return number.isPresent() ? find(scope, document.prompt(), number.getAsInt()) : Optional.empty();
    }

    private Saved save(String scope, String prompt, PromptVersionDocument document, String text, AssembledPrompt version,
                       Integer basedOnNumber, String basedOnHash, String provider, String origin, String originName,
                       String createdBy) {
        String originHash = PromptBundleHashes.sha256Hex(text.replace("\r\n", "\n"));
        Optional<PromptVersionRecord> registered = byOrigin(scope, prompt, origin, originName, originHash);
        if (registered.isPresent()) {
            return new Saved(registered.get().number(), registered.get().name(), registered.get().contentHash(), false);
        }
        TransactionTemplate transaction = new TransactionTemplate(
                new DataSourceTransactionManager(Objects.requireNonNull(jdbc.get().getDataSource())));
        for (int attempt = 1; attempt <= NUMBER_ATTEMPTS; attempt++) {
            int number = nextNumber(scope, prompt);
            try {
                transaction.executeWithoutResult(status -> insert(scope, prompt, number, document, text, version,
                        basedOnNumber, basedOnHash, provider, origin, originName, originHash, createdBy));
                audit.record(PromptVersionAudit.CREATED, scope, prompt, PromptVersionNames.name(number), createdBy,
                        origin + " " + originName);
                return new Saved(number, PromptVersionNames.name(number), version.contentHash(), true);
            }
            catch (DuplicateKeyException collision) {
                Optional<PromptVersionRecord> same = byOrigin(scope, prompt, origin, originName, originHash);
                if (same.isPresent() || String.valueOf(collision.getMessage()).contains(ORIGIN_INDEX)) {
                    PromptVersionRecord found = same.orElseThrow(() -> collision);
                    return new Saved(found.number(), found.name(), found.contentHash(), false);
                }
                // Another save took the number; the next attempt takes the one after.
            }
        }
        throw new IllegalStateException("No version number could be taken for " + prompt + " after " + NUMBER_ATTEMPTS
                + " attempts");
    }

    private void insert(String scope, String prompt, int number, PromptVersionDocument document, String text,
                        AssembledPrompt version, Integer basedOnNumber, String basedOnHash, String provider,
                        String origin, String originName, String originHash, String createdBy) {
        KeyHolder key = new GeneratedKeyHolder();
        String title = document.title() != null && !document.title().isBlank() ? document.title()
                : PromptVersionNames.name(number);
        jdbc.get().update(connection -> {
            PreparedStatement statement = connection.prepareStatement("insert into ctxa_prompt_version (registry_scope,"
                    + " prompt_key, version_number, title, description, based_on_number, based_on_hash, provider,"
                    + " origin, origin_name, origin_content_hash, content_hash, document, hidden, created_by, created_at)"
                    + " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?, ?)", Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, scope);
            statement.setString(2, prompt);
            statement.setInt(3, number);
            statement.setString(4, truncate(title, 256));
            statement.setString(5, truncate(document.description(), 2000));
            statement.setObject(6, basedOnNumber);
            statement.setString(7, basedOnHash);
            statement.setString(8, provider);
            statement.setString(9, origin);
            statement.setString(10, truncate(originName, 512));
            statement.setString(11, originHash);
            statement.setString(12, version.contentHash());
            statement.setString(13, text.replace("\r\n", "\n"));
            statement.setString(14, createdBy != null ? createdBy : "system");
            statement.setTimestamp(15, Timestamp.from(clock.instant()));
            return statement;
        }, key);
        long id = ((Number) Objects.requireNonNull(key.getKeys()).get("id")).longValue();
        int position = 0;
        for (PromptVersionDocument.Part part : document.system()) {
            insertPart(id, "SYSTEM", part, position++);
        }
        for (PromptVersionDocument.Part part : document.user()) {
            insertPart(id, "USER", part, position++);
        }
        for (PromptVersionDocument.Item correction : document.corrections()) {
            jdbc.get().update("insert into ctxa_prompt_version_part (version_id, part_list, part_key, part_action, locked,"
                    + " title, body, add_after, position) values (?, 'CORRECTION', ?, 'BASE', true, null, ?, null, ?)",
                    id, correction.key(), correction.text(), position++);
        }
        RegistryTarget target = targets.get(prompt);
        if (target != null) {
            jdbc.get().update("insert into ctxa_prompt_governance_registry (registry_scope, prompt_key, template_key,"
                    + " prompt_version, contract_version, prompt_artifact_hash_sha256, release_status, owner_name,"
                    + " template_class_name, registration_source, change_summary, created_at, updated_at)"
                    + " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    scope, prompt, target.templateKey(), PromptVersionNames.name(number), target.contractVersion(),
                    version.contentHash(), PromptBundleState.AVAILABLE.name(), target.owner(),
                    target.templateClassName(), "PROMPT_VERSION_" + origin, truncate(title, 2000),
                    Timestamp.from(clock.instant()), Timestamp.from(clock.instant()));
        }
    }

    private void insertPart(long versionId, String list, PromptVersionDocument.Part part, int position) {
        jdbc.get().update("insert into ctxa_prompt_version_part (version_id, part_list, part_key, part_action, locked,"
                + " title, body, add_after, position) values (?, ?, ?, ?, ?, ?, ?, ?, ?)", versionId, list, part.key(),
                part.action().name(), part.locked(), truncate(part.title(), 256), part.text(), part.addAfter(), position);
    }

    private int nextNumber(String scope, String prompt) {
        Integer max = jdbc.get().queryForObject("select max(version_number) from ctxa_prompt_version where"
                + " registry_scope = ? and prompt_key = ?", Integer.class, scope, prompt);
        return (max != null ? max : 0) + 1;
    }

    private Optional<PromptVersionRecord> byOrigin(String scope, String prompt, String origin, String originName,
                                                   String originHash) {
        return jdbc.get().query("select * from ctxa_prompt_version where registry_scope = ? and prompt_key = ? and"
                        + " origin = ? and origin_name = ? and origin_content_hash = ?", ROW, scope, prompt, origin,
                originName, originHash).stream().findFirst();
    }

    /** The version of the number, hidden or not. */
    public Optional<PromptVersionRecord> find(String scope, String prompt, int number) {
        return jdbc.get().query("select * from ctxa_prompt_version where registry_scope = ? and prompt_key = ? and"
                + " version_number = ?", ROW, scopeOf(scope), prompt, number).stream().findFirst();
    }

    /** The versions of the prompt, newest first; hidden ones only when asked. */
    public List<PromptVersionRecord> list(String scope, String prompt, boolean withHidden) {
        return jdbc.get().query("select * from ctxa_prompt_version where registry_scope = ? and prompt_key = ?"
                + (withHidden ? "" : " and hidden = false") + " order by version_number desc", ROW, scopeOf(scope),
                prompt);
    }

    /** The newest version Contexa provided for the prompt (the version a decision runs when nothing else is chosen). */
    public Optional<PromptVersionRecord> latestProduct(String scope, String prompt) {
        return jdbc.get().query("select * from ctxa_prompt_version where registry_scope = ? and prompt_key = ? and"
                + " provider = ? and hidden = false order by version_number desc limit 1", ROW, scopeOf(scope), prompt,
                PromptVersionRecord.CONTEXA).stream().findFirst();
    }

    /**
     * The assembled version of the number: its product document, or its chain of bases with its document applied on
     * top; assembled once and kept, as a version does not change.
     */
    public Optional<AssembledPrompt> assembled(String scope, String prompt, int number) {
        String key = scopeOf(scope) + "|" + prompt + "|" + number;
        AssembledPrompt cached = assembled.get(key);
        if (cached != null) {
            return Optional.of(cached);
        }
        Optional<PromptVersionRecord> record = find(scope, prompt, number);
        if (record.isEmpty()) {
            return Optional.empty();
        }
        PromptVersionDocument document = reader.read(record.get().document());
        AssembledPrompt version;
        if (record.get().basedOnNumber() == null) {
            version = assembler.product(document);
        }
        else {
            AssembledPrompt base = assembled(scope, prompt, record.get().basedOnNumber()).orElseThrow(() ->
                    new IllegalStateException("The base of " + record.get().name() + " is missing"));
            version = assembler.apply(base, document);
        }
        if (!version.contentHash().equals(record.get().contentHash())) {
            log.error("Prompt version {} {} assembles to the content hash {}, not the {} it was saved with", prompt,
                    record.get().name(), version.contentHash(), record.get().contentHash());
        }
        assembled.put(key, version);
        return Optional.of(version);
    }

    /**
     * Hides a version from the lists (plan 3.3); its content stays. A version a decision uses, a canary or a shadow
     * runs cannot be hidden.
     */
    public void hide(String scope, String prompt, int number, String actor) {
        String name = PromptVersionNames.name(number);
        List<String> states = jdbc.get().queryForList("select release_status from ctxa_prompt_governance_registry where"
                + " registry_scope = ? and prompt_key = ? and prompt_version = ?", String.class, scopeOf(scope), prompt,
                name);
        boolean inUse = states.stream().anyMatch(state -> PromptBundleState.is(state, PromptBundleState.ACTIVE)
                || PromptBundleState.is(state, PromptBundleState.CANARY)
                || PromptBundleState.is(state, PromptBundleState.SHADOW));
        if (inUse) {
            throw new PromptVersionDocumentException(List.of(new PromptVersionProblem(PromptVersionProblem.Code.IN_USE,
                    name, null)));
        }
        int updated = jdbc.get().update("update ctxa_prompt_version set hidden = true where registry_scope = ? and"
                + " prompt_key = ? and version_number = ?", scopeOf(scope), prompt, number);
        if (updated == 1) {
            jdbc.get().update("update ctxa_prompt_governance_registry set release_status = ?, updated_at = ? where"
                    + " registry_scope = ? and prompt_key = ? and prompt_version = ?", PromptBundleState.RETIRED.name(),
                    Timestamp.from(clock.instant()), scopeOf(scope), prompt, name);
            audit.record(PromptVersionAudit.HIDDEN, scopeOf(scope), prompt, name, actor, null);
        }
    }

    /**
     * The version as a document (plan 3.6): its changes, which can be imported on another server (its base named by
     * number and content hash), or the whole version rendered for reading, which cannot be imported.
     */
    public Optional<String> export(String scope, String prompt, int number, boolean rendered) {
        Optional<PromptVersionRecord> record = find(scope, prompt, number);
        if (record.isEmpty()) {
            return Optional.empty();
        }
        if (rendered) {
            return assembled(scope, prompt, number).map(version -> writer.writeRendered(version, record.get().title()));
        }
        PromptVersionDocument document = reader.read(record.get().document());
        if (record.get().basedOnNumber() == null) {
            return Optional.of(record.get().document());
        }
        return Optional.of(writer.write(new PromptVersionDocument(document.prompt(),
                PromptVersionDocument.Kind.ORGANIZATION, null, PromptVersionNames.name(record.get().basedOnNumber()),
                "sha256:" + record.get().basedOnHash(), document.title(), document.description(), document.system(),
                document.user(), document.corrections())));
    }

    /** A document imported on the screen (plan 3.6): its base found by its content hash, then saved as a version. */
    public Saved importDocument(String scope, String yaml, String fileName, String actor,
                                PromptAssembler.LengthLimit limit) {
        Saved saved = create(scope, yaml, PromptVersionRecord.IMPORT,
                fileName != null && !fileName.isBlank() ? fileName : "import:" + UUID.randomUUID(), actor, limit);
        if (saved.made()) {
            audit.record(PromptVersionAudit.IMPORTED, scopeOf(scope), reader.read(yaml).prompt(), saved.name(), actor,
                    fileName);
        }
        return saved;
    }

    private static String scopeOf(String scope) {
        return scope != null && !scope.isBlank() ? scope.trim() : PLATFORM_SCOPE;
    }

    private static String truncate(String value, int length) {
        return value == null || value.length() <= length ? value : value.substring(0, length);
    }

    static final RowMapper<PromptVersionRecord> ROW = (rs, row) -> new PromptVersionRecord(
            rs.getLong("id"), rs.getString("registry_scope"), rs.getString("prompt_key"), rs.getInt("version_number"),
            rs.getString("title"), rs.getString("description"), (Integer) rs.getObject("based_on_number"),
            rs.getString("based_on_hash"), rs.getString("provider"), rs.getString("origin"), rs.getString("origin_name"),
            rs.getString("origin_content_hash"), rs.getString("content_hash"), rs.getString("document"),
            rs.getBoolean("hidden"), rs.getString("created_by"),
            rs.getTimestamp("created_at") != null ? rs.getTimestamp("created_at").toInstant() : null);

    /** The bytes of a text as the folder and the import hash them. */
    static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    Instant now() {
        return clock.instant();
    }
}
