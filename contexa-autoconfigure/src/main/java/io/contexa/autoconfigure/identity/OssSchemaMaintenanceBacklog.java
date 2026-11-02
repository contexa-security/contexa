package io.contexa.autoconfigure.identity;

import lombok.extern.slf4j.Slf4j;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * The OSS schema maintenance statements an enterprise start put off. A database older than the code is upgraded in
 * place, and the OSS maintenance runs before the enterprise migrations: a statement such as an index can name a column
 * that only those migrations add. Such a statement waits here and runs once after them; a statement that still fails
 * then stops the start and names itself, so nothing is dropped silently.
 */
@Slf4j
public final class OssSchemaMaintenanceBacklog {

    private final DataSource dataSource;
    private final List<String> pending = new ArrayList<>();

    public OssSchemaMaintenanceBacklog(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    synchronized void defer(List<String> statements) {
        pending.addAll(statements);
    }

    public synchronized int pendingCount() {
        return pending.size();
    }

    /**
     * Runs the put-off statements once. Each statement that succeeds leaves the backlog; the first that fails stops
     * with an {@link IllegalStateException} and stays, with the statements after it.
     */
    public synchronized void complete() {
        if (pending.isEmpty()) {
            return;
        }
        int total = pending.size();
        while (!pending.isEmpty()) {
            String statement = pending.get(0);
            try {
                IamSeedDataAutoConfiguration.executeSchemaSql(dataSource, "db/schema.sql#deferred-maintenance", statement);
            } catch (SQLException error) {
                throw new IllegalStateException("A put-off OSS schema maintenance statement still fails after the "
                        + "enterprise migrations: " + error.getMessage() + ". " + (pending.size() - 1)
                        + " more statement(s) wait behind it.", error);
            }
            pending.remove(0);
        }
        log.info("[IamSeedData] {} put-off OSS schema maintenance statement(s) ran after the enterprise migrations", total);
    }
}
