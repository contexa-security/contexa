package io.contexa.showcase.business.work;

import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;

/**
 * Access to the business database {@code showcase_work}. The plain workload owns it as its primary data source;
 * the Contexa workload reaches it through a separate pool that is not registered as a {@link DataSource} bean, so
 * the application data source of the vector store stays untouched (docs/showcase/ADR.md ADR-10).
 */
public final class WorkDatabase implements AutoCloseable {

    private final DataSource dataSource;
    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final AutoCloseable owned;

    public WorkDatabase(DataSource dataSource, AutoCloseable owned) {
        this.dataSource = dataSource;
        this.jdbc = new NamedParameterJdbcTemplate(dataSource);
        this.transactions = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        this.owned = owned;
    }

    public NamedParameterJdbcTemplate jdbc() {
        return jdbc;
    }

    public TransactionTemplate transactions() {
        return transactions;
    }

    public DataSource dataSource() {
        return dataSource;
    }

    @Override
    public void close() throws Exception {
        if (owned != null) {
            owned.close();
        }
    }
}
