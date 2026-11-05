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
package io.contexa.autoconfigure.core;

import com.zaxxer.hikari.HikariDataSource;
import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacommon.store.RequestBoundDataSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import javax.sql.DataSource;

import static org.assertj.core.api.Assertions.assertThat;

/** Q-7: Contexa's own pool waits about a second for a request, and it stays a pool to everything else. */
class ContexaDataSourceRequestBoundTest {

    private static DataSource contexaDataSource() {
        CoreDataAutoConfiguration configuration = new CoreDataAutoConfiguration();
        configuration.setEnvironment(new MockEnvironment());
        ContexaDataSourceProperties properties = new ContexaDataSourceProperties();
        properties.setUrl("jdbc:postgresql://127.0.0.1:1/contexa");
        properties.setDriverClassName("org.postgresql.Driver");
        return configuration.contexaDataSource(properties, new ContexaStores());
    }

    @Test
    @DisplayName("what a request reads through is bound, and the pool with Contexa's settings is behind it")
    void aRequestReadsThroughTheBoundOne() throws Exception {
        DataSource dataSource = contexaDataSource();

        assertThat(dataSource).isInstanceOf(RequestBoundDataSource.class);
        assertThat(dataSource.unwrap(HikariDataSource.class).getMaximumPoolSize()).isEqualTo(48);
    }

    @Test
    @DisplayName("the pool closes with the bean, as it did when it was the bean")
    void thePoolClosesWithTheBean() throws Exception {
        DataSource dataSource = contexaDataSource();
        HikariDataSource pool = dataSource.unwrap(HikariDataSource.class);

        ((AutoCloseable) dataSource).close();

        assertThat(pool.isClosed()).isTrue();
    }
}
