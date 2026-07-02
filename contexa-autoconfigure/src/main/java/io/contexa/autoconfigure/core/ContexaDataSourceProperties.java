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

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.util.StringUtils;

import javax.sql.DataSource;
import java.lang.reflect.Method;

@ConfigurationProperties("contexa.datasource")
public class ContexaDataSourceProperties {

    private String url;
    private String username;
    private String password;
    private String driverClassName;

    private final Isolation isolation = new Isolation();
    private final Hikari hikari = new Hikari();

    public DataSourceBuilder<?> initializeDataSourceBuilder() {
        DataSourceBuilder<?> builder = DataSourceBuilder.create();
        if (StringUtils.hasText(driverClassName)) {
            builder.driverClassName(driverClassName);
        }
        if (StringUtils.hasText(url)) {
            builder.url(url);
        }
        if (StringUtils.hasText(username)) {
            builder.username(username);
        }
        if (password != null) {
            builder.password(password);
        }
        return builder;
    }

    public DataSource initializeDataSource() {
        DataSource dataSource = initializeDataSourceBuilder().build();
        hikari.applyTo(dataSource);
        return dataSource;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getDriverClassName() {
        return driverClassName;
    }

    public void setDriverClassName(String driverClassName) {
        this.driverClassName = driverClassName;
    }

    public Isolation getIsolation() {
        return isolation;
    }

    public Hikari getHikari() {
        return hikari;
    }

    public static class Isolation {
        private boolean allowSharedApplicationDatasource;
        private boolean sharedApplicationDatasourceRiskAccepted;
        private boolean contexaOwnedApplication;

        public boolean isAllowSharedApplicationDatasource() {
            return allowSharedApplicationDatasource;
        }

        public void setAllowSharedApplicationDatasource(boolean allowSharedApplicationDatasource) {
            this.allowSharedApplicationDatasource = allowSharedApplicationDatasource;
        }

        public boolean isSharedApplicationDatasourceRiskAccepted() {
            return sharedApplicationDatasourceRiskAccepted;
        }

        public void setSharedApplicationDatasourceRiskAccepted(boolean sharedApplicationDatasourceRiskAccepted) {
            this.sharedApplicationDatasourceRiskAccepted = sharedApplicationDatasourceRiskAccepted;
        }

        public boolean isContexaOwnedApplication() {
            return contexaOwnedApplication;
        }

        public void setContexaOwnedApplication(boolean contexaOwnedApplication) {
            this.contexaOwnedApplication = contexaOwnedApplication;
        }
    }
    public static class Hikari {
        private int maximumPoolSize = 48;
        private int minimumIdle = 8;
        private long connectionTimeoutMs = 60000L;
        private long validationTimeoutMs = 5000L;
        private long idleTimeoutMs = 600000L;
        private long maxLifetimeMs = 1800000L;

        void applyTo(DataSource dataSource) {
            if (dataSource == null) {
                return;
            }
            invokeIntSetter(dataSource, "setMaximumPoolSize", maximumPoolSize);
            invokeIntSetter(dataSource, "setMinimumIdle", Math.min(minimumIdle, maximumPoolSize));
            invokeLongSetter(dataSource, "setConnectionTimeout", connectionTimeoutMs);
            invokeLongSetter(dataSource, "setValidationTimeout", validationTimeoutMs);
            invokeLongSetter(dataSource, "setIdleTimeout", idleTimeoutMs);
            invokeLongSetter(dataSource, "setMaxLifetime", maxLifetimeMs);
        }

        private static void invokeIntSetter(DataSource dataSource, String methodName, int value) {
            try {
                Method method = dataSource.getClass().getMethod(methodName, int.class);
                method.invoke(dataSource, value);
            } catch (ReflectiveOperationException | IllegalArgumentException ignored) {
                // Non-Hikari DataSource implementations simply ignore Hikari-specific settings.
            }
        }

        private static void invokeLongSetter(DataSource dataSource, String methodName, long value) {
            try {
                Method method = dataSource.getClass().getMethod(methodName, long.class);
                method.invoke(dataSource, value);
            } catch (ReflectiveOperationException | IllegalArgumentException ignored) {
                // Non-Hikari DataSource implementations simply ignore Hikari-specific settings.
            }
        }

        public int getMaximumPoolSize() {
            return maximumPoolSize;
        }

        public void setMaximumPoolSize(int maximumPoolSize) {
            this.maximumPoolSize = maximumPoolSize;
        }

        public int getMinimumIdle() {
            return minimumIdle;
        }

        public void setMinimumIdle(int minimumIdle) {
            this.minimumIdle = minimumIdle;
        }

        public long getConnectionTimeoutMs() {
            return connectionTimeoutMs;
        }

        public void setConnectionTimeoutMs(long connectionTimeoutMs) {
            this.connectionTimeoutMs = connectionTimeoutMs;
        }

        public long getValidationTimeoutMs() {
            return validationTimeoutMs;
        }

        public void setValidationTimeoutMs(long validationTimeoutMs) {
            this.validationTimeoutMs = validationTimeoutMs;
        }

        public long getIdleTimeoutMs() {
            return idleTimeoutMs;
        }

        public void setIdleTimeoutMs(long idleTimeoutMs) {
            this.idleTimeoutMs = idleTimeoutMs;
        }

        public long getMaxLifetimeMs() {
            return maxLifetimeMs;
        }

        public void setMaxLifetimeMs(long maxLifetimeMs) {
            this.maxLifetimeMs = maxLifetimeMs;
        }
    }
}
