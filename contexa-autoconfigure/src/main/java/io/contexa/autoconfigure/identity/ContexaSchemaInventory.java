package io.contexa.autoconfigure.identity;

import org.springframework.core.io.Resource;

import javax.sql.DataSource;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Machine-readable, checksum-versioned schema ownership inventory. */
public final class ContexaSchemaInventory {

    private static final Pattern CREATE_OBJECT = Pattern.compile(
            "(?is)^create\\s+(?:or\\s+replace\\s+)?(materialized\\s+view|table|view)\\s+"
                    + "(?:if\\s+not\\s+exists\\s+)?(?:public\\.)?\\x22?([a-zA-Z0-9_]+)\\x22?");
    private static final Pattern DROP_OBJECT = Pattern.compile(
            "(?is)^drop\\s+(materialized\\s+view|table|view)\\s+"
                    + "(?:if\\s+exists\\s+)?(?:public\\.)?\\x22?([a-zA-Z0-9_]+)\\x22?");
    private static final Pattern RENAME_TABLE = Pattern.compile(
            "(?is)^alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:public\\.)?"
                    + "\\x22?([a-zA-Z0-9_]+)\\x22?\\s+rename\\s+to\\s+"
                    + "\\x22?([a-zA-Z0-9_]+)\\x22?");
    private static final Pattern MIGRATION_FILE = Pattern.compile("^(V[^_]+(?:_[^_]+)*)__.+\\.sql$");

    private ContexaSchemaInventory() {
    }

    public static Snapshot fromResources(String owner, Collection<Resource> resources) throws IOException {
        MessageDigest digest = sha256();
        Set<String> tables = new TreeSet<>();
        Set<String> views = new TreeSet<>();
        Set<String> migrations = new TreeSet<>();
        List<Resource> ordered = new ArrayList<>(resources);
        ordered.sort((left, right) -> resourceIdentity(left).compareTo(resourceIdentity(right)));
        for (Resource resource : ordered) {
            byte[] bytes = resource.getContentAsByteArray();
            String identity = resourceIdentity(resource);
            digest.update(identity.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(bytes);
            String sql = new String(bytes, StandardCharsets.UTF_8);
            for (String statement : IamSeedDataAutoConfiguration.splitSqlStatements(sql)) {
                String candidate = statement
                        .replaceAll("(?s)/\\*.*?\\*/", " ")
                        .replaceAll("(?m)--.*$", " ")
                        .trim();
                Matcher create = CREATE_OBJECT.matcher(candidate);
                if (create.find()) {
                    addObject(create.group(1), create.group(2), tables, views);
                    continue;
                }
                Matcher drop = DROP_OBJECT.matcher(candidate);
                if (drop.find()) {
                    removeObject(drop.group(1), drop.group(2), tables, views);
                    continue;
                }
                Matcher rename = RENAME_TABLE.matcher(candidate);
                if (rename.find()) {
                    String previousName = rename.group(1).toLowerCase(Locale.ROOT);
                    if (tables.remove(previousName)) {
                        tables.add(rename.group(2).toLowerCase(Locale.ROOT));
                    }
                }
            }
            String filename = resource.getFilename();
            if (filename != null) {
                Matcher migration = MIGRATION_FILE.matcher(filename);
                if (migration.matches()) {
                    migrations.add(filename.substring(0, filename.length() - 4));
                }
            }
        }
        if (!migrations.isEmpty()) {
            tables.add("flyway_schema_history");
        }
        String checksum = HexFormat.of().formatHex(digest.digest());
        String version = owner.toLowerCase(Locale.ROOT) + "-" + checksum.substring(0, 16);
        return new Snapshot(owner, version, checksum, tables, views, migrations);
    }

    private static String resourceIdentity(Resource resource) {
        String filename = resource.getFilename();
        return filename == null ? resource.getDescription() : filename;
    }

    private static void addObject(String type, String objectName, Set<String> tables, Set<String> views) {
        String name = objectName.toLowerCase(Locale.ROOT);
        if (type.toLowerCase(Locale.ROOT).contains("view")) {
            views.add(name);
        } else {
            tables.add(name);
        }
    }

    private static void removeObject(String type, String objectName, Set<String> tables, Set<String> views) {
        String name = objectName.toLowerCase(Locale.ROOT);
        if (type.toLowerCase(Locale.ROOT).contains("view")) {
            views.remove(name);
        } else {
            tables.remove(name);
        }
    }

    public static Snapshot subtract(Snapshot full, Snapshot base) {
        Set<String> tables = new TreeSet<>(full.tables());
        tables.removeAll(base.tables());
        Set<String> views = new TreeSet<>(full.views());
        views.removeAll(base.views());
        return new Snapshot(full.owner(), full.version(), full.checksum(), tables, views, full.migrations());
    }

    public static Snapshot fromDatabaseObjects(String owner, DatabaseObjects objects) {
        MessageDigest digest = sha256();
        digest.update(owner.getBytes(StandardCharsets.UTF_8));
        new TreeSet<>(objects.tables()).forEach(table -> updateDigest(digest, "TABLE", table));
        new TreeSet<>(objects.views()).forEach(view -> updateDigest(digest, "VIEW", view));
        String checksum = HexFormat.of().formatHex(digest.digest());
        return new Snapshot(
                owner,
                owner.toLowerCase(Locale.ROOT) + "-" + checksum.substring(0, 16),
                checksum,
                objects.tables(),
                objects.views(),
                Set.of());
    }

    public static DatabaseObjects subtract(DatabaseObjects actual, Collection<Snapshot> owned) {
        Set<String> tables = new TreeSet<>(actual.tables());
        Set<String> views = new TreeSet<>(actual.views());
        owned.forEach(inventory -> {
            tables.removeAll(inventory.tables());
            views.removeAll(inventory.views());
        });
        return new DatabaseObjects(tables, views);
    }

    public static DatabaseObjects intersection(DatabaseObjects actual, Snapshot inventory) {
        Set<String> tables = new TreeSet<>(actual.tables());
        tables.retainAll(inventory.tables());
        Set<String> views = new TreeSet<>(actual.views());
        views.retainAll(inventory.views());
        return new DatabaseObjects(tables, views);
    }

    public static DatabaseObjects readDatabase(DataSource dataSource) throws SQLException {
        Set<String> tables = new TreeSet<>();
        Set<String> views = new TreeSet<>();
        try (Connection connection = dataSource.getConnection();
             ResultSet objects = connection.getMetaData().getTables(
                     connection.getCatalog(), "public", "%", new String[]{"TABLE", "VIEW", "MATERIALIZED VIEW"})) {
            while (objects.next()) {
                String name = objects.getString("TABLE_NAME").toLowerCase(Locale.ROOT);
                String type = objects.getString("TABLE_TYPE").toUpperCase(Locale.ROOT);
                if (type.contains("VIEW")) {
                    views.add(name);
                } else {
                    tables.add(name);
                }
            }
        }
        return new DatabaseObjects(tables, views);
    }

    public static Diff diff(Snapshot required, DatabaseObjects actual) {
        Set<String> missingTables = new TreeSet<>(required.tables());
        missingTables.removeAll(actual.tables());
        Set<String> missingViews = new TreeSet<>(required.views());
        missingViews.removeAll(actual.views());
        Set<String> additionalTables = new TreeSet<>(actual.tables());
        additionalTables.removeAll(required.tables());
        Set<String> additionalViews = new TreeSet<>(actual.views());
        additionalViews.removeAll(required.views());
        return new Diff(missingTables, missingViews, additionalTables, additionalViews);
    }

    public record Snapshot(
            String owner,
            String version,
            String checksum,
            Set<String> tables,
            Set<String> views,
            Set<String> migrations) {

        public Snapshot {
            tables = Set.copyOf(tables);
            views = Set.copyOf(views);
            migrations = Set.copyOf(migrations);
        }
    }

    public record DatabaseObjects(Set<String> tables, Set<String> views) {

        public DatabaseObjects {
            tables = Set.copyOf(tables);
            views = Set.copyOf(views);
        }
    }

    public record Diff(
            Set<String> missingTables,
            Set<String> missingViews,
            Set<String> additionalTables,
            Set<String> additionalViews) {

        public Diff {
            missingTables = Set.copyOf(missingTables);
            missingViews = Set.copyOf(missingViews);
            additionalTables = Set.copyOf(additionalTables);
            additionalViews = Set.copyOf(additionalViews);
        }

        public boolean complete() {
            return missingTables.isEmpty() && missingViews.isEmpty();
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required", e);
        }
    }

    private static void updateDigest(MessageDigest digest, String type, String name) {
        digest.update(type.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) '|');
        digest.update(name.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) '\n');
    }
}
