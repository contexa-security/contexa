package io.contexa.demo.workspace.evidence.persistence;

import io.contexa.demo.observation.configuration.EvidenceStoreProperties;
import io.contexa.demo.workspace.evidence.service.WorkspaceEvidenceScope;
import org.springframework.jdbc.datasource.AbstractDataSource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class GenerationEvidenceDataSource extends AbstractDataSource implements AutoCloseable {

    private final DataSource current;
    private final WorkspaceEvidenceScope scope;
    private final EvidenceStoreProperties properties;
    private final String role;
    private final Semaphore archiveConnections = new Semaphore(2, true);

    public GenerationEvidenceDataSource(DataSource current, WorkspaceEvidenceScope scope,
            EvidenceStoreProperties properties, String role) {
        this.current = current;
        this.scope = scope;
        this.properties = properties;
        this.role = role;
    }

    @Override
    public Connection getConnection() throws SQLException {
        String url = scope.currentUrl(role);
        if (url == null) {
            return current.getConnection();
        }
        try {
            if (!archiveConnections.tryAcquire(2, TimeUnit.SECONDS)) {
                throw new SQLException("Archived evidence connections are busy");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new SQLException("Archived evidence read interrupted", interrupted);
        }
        Connection connection;
        try {
            String connectionUrl = url + (url.contains("?") ? "&" : "?") + "connectTimeout=2&socketTimeout=3";
            connection = new DriverManagerDataSource(connectionUrl, properties.username(), properties.password()).getConnection();
        } catch (SQLException unavailable) {
            archiveConnections.release();
            throw unavailable;
        }
        try {
            connection.setReadOnly(true);
        } catch (SQLException unavailable) {
            try {
                connection.close();
            } finally {
                archiveConnections.release();
            }
            throw unavailable;
        }
        AtomicBoolean closed = new AtomicBoolean();
        return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(), new Class<?>[]{Connection.class},
                (proxy, method, arguments) -> {
                    try {
                        return method.invoke(connection, arguments);
                    } catch (InvocationTargetException failure) {
                        throw failure.getCause();
                    } finally {
                        if (method.getName().equals("close") && closed.compareAndSet(false, true)) {
                            archiveConnections.release();
                        }
                    }
                });
    }

    @Override
    public Connection getConnection(String username, String password) throws SQLException {
        throw new SQLException("Evidence reads use the configured read-only credentials");
    }

    @Override
    public void close() throws Exception {
        if (current instanceof AutoCloseable closeable) {
            closeable.close();
        }
    }
}
