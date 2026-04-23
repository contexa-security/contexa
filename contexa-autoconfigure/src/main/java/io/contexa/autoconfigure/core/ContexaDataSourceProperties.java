package io.contexa.autoconfigure.core;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.util.StringUtils;

@ConfigurationProperties("contexa.datasource")
public class ContexaDataSourceProperties {

    private String url;
    private String username;
    private String password;
    private String driverClassName;

    private final Isolation isolation = new Isolation();

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
}
