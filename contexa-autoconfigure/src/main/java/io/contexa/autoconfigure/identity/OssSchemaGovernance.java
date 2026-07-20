package io.contexa.autoconfigure.identity;

import io.contexa.contexaiam.admin.promptquality.official.common.OfficialVerificationDefinitionCatalogWriter;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialVerificationDefinitionCatalogWriter.CatalogSnapshot;
import org.springframework.core.io.ClassPathResource;

import javax.sql.DataSource;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/** Coordinates OSS catalog, inventory, and provenance without running migrations. */
public final class OssSchemaGovernance {

    public static final String OSS_OWNER = "OSS";
    public static final String ENTERPRISE_OWNER = "ENTERPRISE";
    public static final String HOST_OWNER = "HOST";
    public static final String LEGACY_UNOWNED_OWNER = "LEGACY_UNOWNED";
    private static final String OSS_SCHEMA = "db/schema.sql";

    private final DataSource dataSource;
    private final OfficialVerificationDefinitionCatalogWriter catalogWriter;

    public OssSchemaGovernance(DataSource dataSource) {
        this.dataSource = dataSource;
        this.catalogWriter = new OfficialVerificationDefinitionCatalogWriter(dataSource);
    }

    public GovernanceReport initializeAndRecordOss() throws SQLException, IOException {
        return initializeAndRecordOss(null);
    }

    public GovernanceReport initializeAndRecordOss(
            ContexaSchemaInventory.DatabaseObjects preInstallationHostObjects) throws SQLException, IOException {
        CatalogSnapshot catalog = catalogWriter.upsertAndVerify();
        ContexaSchemaInventory.Snapshot inventory = ossInventory();
        ContexaSchemaInventory.Diff diff = ContexaSchemaInventory.diff(
                inventory, ContexaSchemaInventory.readDatabase(dataSource));
        requireComplete(inventory.owner(), diff);
        recordInventory(OSS_OWNER, inventory, catalog, null);
        ensureHostInventory(preInstallationHostObjects);
        OwnershipClassification ownership = recordOwnershipClassification(inventory);
        return new GovernanceReport(inventory, diff, catalog, null, ownership);
    }

    public void assertNoOssOwnershipCollisions(
            ContexaSchemaInventory.DatabaseObjects preInstallationObjects) throws IOException {
        ContexaSchemaInventory.DatabaseObjects collisions = ContexaSchemaInventory.intersection(
                preInstallationObjects, ossInventory());
        if (!collisions.tables().isEmpty() || !collisions.views().isEmpty()) {
            throw new IllegalStateException("Existing host schema collides with OSS-owned objects. tables="
                    + collisions.tables() + ", views=" + collisions.views());
        }
    }

    public GovernanceReport verifyOssHandoff() throws SQLException, IOException {
        CatalogSnapshot catalog = catalogWriter.verify();
        ContexaSchemaInventory.Snapshot inventory = ossInventory();
        ContexaSchemaInventory.Diff diff = ContexaSchemaInventory.diff(
                inventory, ContexaSchemaInventory.readDatabase(dataSource));
        requireComplete(inventory.owner(), diff);
        Provenance provenance = readProvenance(OSS_OWNER);
        boolean catalogMatches = provenance != null
                && catalog.version().equals(provenance.catalogVersion())
                && catalog.checksum().equals(provenance.catalogChecksum());
        boolean canonicalVersionMatches = provenance != null
                && inventory.version().equals(provenance.schemaVersion())
                && inventory.checksum().equals(provenance.inventoryChecksum());
        boolean verifiedVersionUpgrade = provenance != null
                && sameOwnedObjects(inventory, readInventory(OSS_OWNER));
        if (!catalogMatches || (!canonicalVersionMatches && !verifiedVersionUpgrade)) {
            throw new IllegalStateException("OSS schema provenance does not match the canonical inventory and catalog");
        }
        OwnershipClassification ownership = currentOwnershipClassification(inventory);
        return new GovernanceReport(inventory, diff, catalog, provenance.migrationVersion(), ownership);
    }

    public boolean hasProvenance(String owner) throws SQLException {
        if (!provenanceTableExists()) {
            return false;
        }
        return readProvenance(owner) != null;
    }

    public GovernanceReport refreshCatalogAfterEnterpriseMigration() throws SQLException, IOException {
        CatalogSnapshot catalog = catalogWriter.upsertAndVerify();
        ContexaSchemaInventory.Snapshot inventory = ossInventory();
        ContexaSchemaInventory.Diff diff = ContexaSchemaInventory.diff(
                inventory, ContexaSchemaInventory.readDatabase(dataSource));
        requireComplete(inventory.owner(), diff);
        recordInventory(OSS_OWNER, inventory, catalog, null);
        OwnershipClassification ownership = recordOwnershipClassification(inventory);
        return new GovernanceReport(inventory, diff, catalog, null, ownership);
    }

    public GovernanceReport recordEnterprise(
            ContexaSchemaInventory.Snapshot inventory,
            String migrationVersion) throws SQLException, IOException {
        CatalogSnapshot catalog = catalogWriter.verify();
        ContexaSchemaInventory.Diff diff = ContexaSchemaInventory.diff(
                inventory, ContexaSchemaInventory.readDatabase(dataSource));
        requireComplete(inventory.owner(), diff);
        recordInventory(ENTERPRISE_OWNER, inventory, catalog, migrationVersion);
        OwnershipClassification ownership = recordOwnershipClassification(ossInventory());
        return new GovernanceReport(inventory, diff, catalog, migrationVersion, ownership);
    }

    public ContexaSchemaInventory.Snapshot ossInventory() throws IOException {
        return ContexaSchemaInventory.fromResources(
                OSS_OWNER, List.of(new ClassPathResource(OSS_SCHEMA)));
    }

    static boolean sameOwnedObjects(
            ContexaSchemaInventory.Snapshot expected,
            ContexaSchemaInventory.Snapshot recorded) {
        return recorded != null
                && expected.tables().equals(recorded.tables())
                && expected.views().equals(recorded.views())
                && expected.migrations().equals(recorded.migrations());
    }

    private void requireComplete(String owner, ContexaSchemaInventory.Diff diff) {
        if (!diff.complete()) {
            throw new IllegalStateException(owner + " schema inventory is incomplete. missingTables="
                    + diff.missingTables() + ", missingViews=" + diff.missingViews());
        }
    }

    private void ensureHostInventory(
            ContexaSchemaInventory.DatabaseObjects preInstallationHostObjects) throws SQLException {
        if (readInventory(HOST_OWNER) != null) {
            return;
        }
        ContexaSchemaInventory.DatabaseObjects hostObjects = preInstallationHostObjects == null
                ? new ContexaSchemaInventory.DatabaseObjects(Set.of(), Set.of())
                : preInstallationHostObjects;
        recordInventory(
                HOST_OWNER,
                ContexaSchemaInventory.fromDatabaseObjects(HOST_OWNER, hostObjects),
                null,
                null);
    }

    private OwnershipClassification recordOwnershipClassification(
            ContexaSchemaInventory.Snapshot ossInventory) throws SQLException {
        OwnershipClassification classification = currentOwnershipClassification(ossInventory);
        recordInventory(LEGACY_UNOWNED_OWNER, classification.unowned(), null, null);
        return classification;
    }

    private OwnershipClassification currentOwnershipClassification(
            ContexaSchemaInventory.Snapshot ossInventory) throws SQLException {
        ContexaSchemaInventory.Snapshot host = readInventory(HOST_OWNER);
        if (host == null) {
            host = ContexaSchemaInventory.fromDatabaseObjects(
                    HOST_OWNER, new ContexaSchemaInventory.DatabaseObjects(Set.of(), Set.of()));
        }
        List<ContexaSchemaInventory.Snapshot> owned = new ArrayList<>();
        owned.add(ossInventory);
        owned.add(host);
        ContexaSchemaInventory.Snapshot enterprise = readInventory(ENTERPRISE_OWNER);
        if (enterprise != null) {
            owned.add(enterprise);
        }
        ContexaSchemaInventory.DatabaseObjects unownedObjects = ContexaSchemaInventory.subtract(
                ContexaSchemaInventory.readDatabase(dataSource), owned);
        ContexaSchemaInventory.Snapshot unowned = ContexaSchemaInventory.fromDatabaseObjects(
                LEGACY_UNOWNED_OWNER, unownedObjects);
        return new OwnershipClassification(host, unowned);
    }

    private ContexaSchemaInventory.Snapshot readInventory(String owner) throws SQLException {
        Provenance provenance = readProvenance(owner);
        if (provenance == null) {
            return null;
        }
        Set<String> tables = new TreeSet<>();
        Set<String> views = new TreeSet<>();
        Set<String> migrations = new TreeSet<>();
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     select object_type, object_name
                       from contexa_schema_inventory_object
                      where product_owner = ?
                      order by object_type, object_name
                     """)) {
            statement.setString(1, owner);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    String type = resultSet.getString(1);
                    String name = resultSet.getString(2);
                    if ("TABLE".equals(type)) {
                        tables.add(name);
                    } else if ("VIEW".equals(type)) {
                        views.add(name);
                    } else if ("MIGRATION".equals(type)) {
                        migrations.add(name);
                    }
                }
            }
        }
        return new ContexaSchemaInventory.Snapshot(
                owner,
                provenance.schemaVersion(),
                provenance.inventoryChecksum(),
                tables,
                views,
                migrations);
    }

    private void recordInventory(
            String owner,
            ContexaSchemaInventory.Snapshot inventory,
            CatalogSnapshot catalog,
            String migrationVersion) throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            boolean previousAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try {
                upsertProvenance(connection, owner, inventory, catalog, migrationVersion);
                replaceInventoryObjects(connection, owner, inventory);
                connection.commit();
            } catch (SQLException error) {
                connection.rollback();
                throw error;
            } finally {
                connection.setAutoCommit(previousAutoCommit);
            }
        }
    }

    private void upsertProvenance(
            Connection connection,
            String owner,
            ContexaSchemaInventory.Snapshot inventory,
            CatalogSnapshot catalog,
            String migrationVersion) throws SQLException {
        int updated;
        try (PreparedStatement statement = connection.prepareStatement("""
                update contexa_schema_provenance
                   set schema_version = ?, inventory_checksum = ?, catalog_version = ?,
                       catalog_checksum = ?, migration_version = ?, recorded_at = current_timestamp
                 where product_owner = ?
                """)) {
            bindProvenance(statement, inventory, catalog, migrationVersion, owner, false);
            updated = statement.executeUpdate();
        }
        if (updated == 0) {
            try (PreparedStatement statement = connection.prepareStatement("""
                    insert into contexa_schema_provenance
                        (product_owner, schema_version, inventory_checksum, catalog_version,
                         catalog_checksum, migration_version)
                    values (?, ?, ?, ?, ?, ?)
                    """)) {
                bindProvenance(statement, inventory, catalog, migrationVersion, owner, true);
                statement.executeUpdate();
            }
        }
    }

    private void replaceInventoryObjects(
            Connection connection,
            String owner,
            ContexaSchemaInventory.Snapshot inventory) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "delete from contexa_schema_inventory_object where product_owner = ?")) {
            statement.setString(1, owner);
            statement.executeUpdate();
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                insert into contexa_schema_inventory_object
                    (product_owner, inventory_version, object_type, object_name)
                values (?, ?, ?, ?)
                """)) {
            addInventoryObjects(statement, owner, inventory.version(), "TABLE", inventory.tables());
            addInventoryObjects(statement, owner, inventory.version(), "VIEW", inventory.views());
            addInventoryObjects(statement, owner, inventory.version(), "MIGRATION", inventory.migrations());
            statement.executeBatch();
        }
    }

    private void addInventoryObjects(
            PreparedStatement statement,
            String owner,
            String version,
            String type,
            Set<String> names) throws SQLException {
        for (String name : new TreeSet<>(names)) {
            statement.setString(1, owner);
            statement.setString(2, version);
            statement.setString(3, type);
            statement.setString(4, name);
            statement.addBatch();
        }
    }

    private void bindProvenance(
            PreparedStatement statement,
            ContexaSchemaInventory.Snapshot inventory,
            CatalogSnapshot catalog,
            String migrationVersion,
            String owner,
            boolean insert) throws SQLException {
        if (insert) {
            statement.setString(1, owner);
            statement.setString(2, inventory.version());
            statement.setString(3, inventory.checksum());
            statement.setString(4, catalog == null ? null : catalog.version());
            statement.setString(5, catalog == null ? null : catalog.checksum());
            statement.setString(6, migrationVersion);
        } else {
            statement.setString(1, inventory.version());
            statement.setString(2, inventory.checksum());
            statement.setString(3, catalog == null ? null : catalog.version());
            statement.setString(4, catalog == null ? null : catalog.checksum());
            statement.setString(5, migrationVersion);
            statement.setString(6, owner);
        }
    }

    private Provenance readProvenance(String owner) throws SQLException {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     select schema_version, inventory_checksum, catalog_version,
                            catalog_checksum, migration_version
                       from contexa_schema_provenance
                      where product_owner = ?
                     """)) {
            statement.setString(1, owner);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return null;
                }
                return new Provenance(
                        resultSet.getString(1),
                        resultSet.getString(2),
                        resultSet.getString(3),
                        resultSet.getString(4),
                        resultSet.getString(5));
            }
        }
    }

    private boolean provenanceTableExists() throws SQLException {
        try (Connection connection = dataSource.getConnection();
             ResultSet tables = connection.getMetaData().getTables(
                     connection.getCatalog(), "public", "contexa_schema_provenance", new String[]{"TABLE"})) {
            return tables.next();
        }
    }

    public record GovernanceReport(
            ContexaSchemaInventory.Snapshot inventory,
            ContexaSchemaInventory.Diff diff,
            CatalogSnapshot catalog,
            String migrationVersion,
            OwnershipClassification ownership) {
    }

    public record OwnershipClassification(
            ContexaSchemaInventory.Snapshot host,
            ContexaSchemaInventory.Snapshot unowned) {
    }

    private record Provenance(
            String schemaVersion,
            String inventoryChecksum,
            String catalogVersion,
            String catalogChecksum,
            String migrationVersion) {
    }
}
