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
package io.contexa.autoconfigure.iam;

import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import io.contexa.contexaiam.admin.web.auth.controller.SessionManagementController;
import io.contexa.contexaiam.admin.web.auth.service.ActiveSessionReferences;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.domain.entity.ActiveSession;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.orm.jpa.persistenceunit.PersistenceManagedTypes;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.ui.ConcurrentModel;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A session an older node tracked under the value its cookie carries, after the references were introduced, is shown,
 * exported and ended by its reference: a node that is not yet on references goes on writing the raw value while the
 * console already runs on references (a rolling upgrade), and what it wrote must not wait for the next start to be
 * turned into a reference. It runs on a real PostgreSQL database, through the console's controller over Spring's real
 * transaction proxies.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class RawSessionRowsPostgresTest {

    private static final String RAW = "6F1C2A9B8E7D4C3B2A1908F7E6D5C4B3";
    private static final LocalDateTime AT = LocalDateTime.of(2026, 11, 6, 9, 0);

    private PostgresTestDatabase database;
    private LocalContainerEntityManagerFactoryBean entityManagers;
    private AnnotationConfigApplicationContext console;
    private JdbcTemplate jdbc;
    private SessionManagementController controller;

    @Configuration
    @EnableTransactionManagement
    static class Transactions {
    }

    @BeforeEach
    void aConsoleOnTheSessionTable() throws Exception {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        jdbc.execute(activeSessionsDdl());

        entityManagers = new LocalContainerEntityManagerFactoryBean();
        entityManagers.setDataSource(database.dataSource());
        entityManagers.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        entityManagers.setPersistenceUnitName("contexa");
        entityManagers.setManagedTypes(PersistenceManagedTypes.of(ActiveSession.class.getName()));
        entityManagers.setJpaPropertyMap(Map.of(
                "hibernate.physical_naming_strategy",
                "org.hibernate.boot.model.naming.CamelCaseToUnderscoresNamingStrategy",
                "hibernate.implicit_naming_strategy",
                "org.springframework.boot.orm.jpa.hibernate.SpringImplicitNamingStrategy"));
        entityManagers.afterPropertiesSet();
        EntityManager entityManager = SharedEntityManagerCreator.createSharedEntityManager(entityManagers.getObject());
        ActiveSessionRepository sessions = new JpaRepositoryFactory(entityManager)
                .getRepository(ActiveSessionRepository.class);

        console = new AnnotationConfigApplicationContext();
        console.register(Transactions.class);
        console.registerBean("contexaTransactionManager", JpaTransactionManager.class,
                () -> new JpaTransactionManager(entityManagers.getObject()));
        console.registerBean("sessionManagementService", SessionManagementService.class,
                () -> new SessionManagementService(sessions, new ActiveSessionReferences(jdbc)));
        ResourceBundleMessageSource messages = new ResourceBundleMessageSource();
        messages.setBasename("contexa/i18n/messages");
        messages.setDefaultEncoding("UTF-8");
        messages.setUseCodeAsDefaultMessage(true);
        messages.setFallbackToSystemLocale(false);
        console.registerBean("sessionManagementController", SessionManagementController.class,
                () -> new SessionManagementController(console.getBean(SessionManagementService.class), messages,
                        new CsvExportService()));
        console.refresh();
        controller = console.getBean(SessionManagementController.class);
    }

    @AfterEach
    void close() {
        if (console != null) {
            console.close();
        }
        if (entityManagers != null) {
            entityManagers.destroy();
        }
        if (database != null) {
            database.close();
        }
    }

    @Test
    void endingASessionAnOlderNodeTrackedUnderItsRawValueEndsIt() {
        row(RAW, "alice", false);
        controller.list(0, null, new ConcurrentModel());

        controller.invalidateSession(ref(RAW), new RedirectAttributesModelMap());

        assertThat(jdbc.queryForList("select session_id from ctxa_active_sessions where not expired", String.class))
                .as("sessions that still run").isEmpty();
        assertThat(expired(ref(RAW))).isTrue();
    }

    @Test
    void theListTurnsTheRowsOfOlderNodesIntoTheirReferences() {
        row(RAW, "alice", false);
        row("ANOTHER-RAW-VALUE", "bob", false);
        row(ref("ALREADY-A-REFERENCE"), "carol", false);

        ConcurrentModel model = new ConcurrentModel();
        controller.list(0, null, model);

        assertThat(jdbc.queryForList("select session_id from ctxa_active_sessions", String.class))
                .containsExactlyInAnyOrder(ref(RAW), ref("ANOTHER-RAW-VALUE"), ref("ALREADY-A-REFERENCE"))
                .allMatch(id -> id.matches("sid-[0-9a-f]{24}"));
    }

    @Test
    void aSessionForcedOutUnderItsRawValueStaysForcedOutOnceTheRowIsMoved() {
        // An older node tracked the session again, under the raw value, while a newer node had it as a reference.
        row(RAW, "alice", true);
        row(ref(RAW), "alice", false);
        row("OTHER-RAW", "bob", false);
        row(ref("OTHER-RAW"), "bob", true);

        controller.list(0, null, new ConcurrentModel());

        assertThat(jdbc.queryForList("select session_id from ctxa_active_sessions", String.class))
                .containsExactlyInAnyOrder(ref(RAW), ref("OTHER-RAW"));
        assertThat(expired(ref(RAW))).isTrue();
        assertThat(expired(ref("OTHER-RAW"))).isTrue();
    }

    @Test
    void theExportNamesNoRawValue() throws Exception {
        row(RAW, "alice", false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        controller.export(response);

        String csv = response.getContentAsString(StandardCharsets.UTF_8);
        assertThat(csv).doesNotContain(RAW).contains(ref(RAW));
        assertThat(jdbc.queryForList("select session_id from ctxa_active_sessions", String.class))
                .containsExactly(ref(RAW));
    }

    @Test
    void readingTwiceMovesNothingTheSecondTime() {
        row(RAW, "alice", false);
        controller.list(0, null, new ConcurrentModel());
        List<Map<String, Object>> once = jdbc.queryForList("select * from ctxa_active_sessions order by session_id");

        controller.list(0, null, new ConcurrentModel());

        assertThat(jdbc.queryForList("select * from ctxa_active_sessions order by session_id")).isEqualTo(once);
    }

    private void row(String sessionId, String user, boolean expired) {
        jdbc.update("insert into ctxa_active_sessions (session_id, client_ip, created_at, expired, last_accessed_at, "
                        + "user_agent, user_id, username) values (?, ?, ?, ?, ?, ?, ?, ?)", sessionId, "10.0.0.7",
                Timestamp.valueOf(AT), expired, Timestamp.valueOf(AT.plusMinutes(5)), "browser", user, user);
    }

    private boolean expired(String sessionId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("select expired from ctxa_active_sessions where session_id = ?",
                Boolean.class, sessionId));
    }

    private static String ref(String sessionId) {
        return RequestFactRedaction.sessionReference(sessionId);
    }

    /** The table exactly as the canonical schema creates it. */
    private static String activeSessionsDdl() throws Exception {
        String schema = new ClassPathResource("META-INF/contexa/db/schema.sql").getContentAsString(StandardCharsets.UTF_8);
        Matcher table = Pattern.compile("(?is)create table ctxa_active_sessions\\s*\\(.*?\\n\\);").matcher(schema);
        assertThat(table.find()).isTrue();
        return table.group().replace(";", "");
    }
}
