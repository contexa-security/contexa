package io.contexa.demo.shared.persistence;

import org.springframework.jdbc.core.JdbcOperations;

import java.util.List;

public abstract class AbstractJdbcRepository {

    protected final JdbcOperations jdbc;

    protected AbstractJdbcRepository(JdbcOperations jdbc) {
        this.jdbc = jdbc;
    }

    protected <T> T first(List<T> values) {
        return values.isEmpty() ? null : values.get(0);
    }
}
