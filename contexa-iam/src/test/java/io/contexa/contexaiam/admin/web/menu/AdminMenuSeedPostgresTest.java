/*
 * Copyright 2026 The Contexa Project
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.admin.web.menu;

import io.contexa.contexaiam.testsupport.PostgresTestDatabase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Console plan 5-1: the menu seed, applied as an installation applies it, to a new database and to one that still holds
 * the AI monitor's menus.
 */
@EnabledIfEnvironmentVariable(named = "CONTEXA_TEST_DB_URL", matches = ".+")
class AdminMenuSeedPostgresTest {

    private static PostgresTestDatabase database;
    private static JdbcTemplate jdbc;

    @BeforeAll
    static void aDatabaseWithTheSchemaAndTheSeed() throws Exception {
        database = PostgresTestDatabase.empty();
        jdbc = database.jdbcTemplate();
        run("META-INF/contexa/db/schema.sql");
        run("META-INF/contexa/db/data-menu.sql");
    }

    @AfterAll
    static void close() {
        if (database != null) {
            database.close();
        }
    }

    @Test
    @DisplayName("the seed puts the console's six screens and the user bridge status under the Zero Trust group and renames the event log")
    void theSeedPutsTheConsoleScreens() {
        assertThat(screens()).containsExactly(
                "1 menu.zerotrust.overview /contexa/admin/zero-trust zero-trust-overview",
                "2 menu.zerotrust.impact /contexa/admin/zero-trust/impact zero-trust-impact",
                "3 menu.zerotrust.trust /contexa/admin/zero-trust/trust zero-trust-trust",
                "4 menu.zerotrust.decisions /contexa/admin/zero-trust/decisions zero-trust-decisions",
                "5 menu.zerotrust.adoption /contexa/admin/zero-trust/adoption zero-trust-adoption",
                "6 menu.zerotrust.operations /contexa/admin/zero-trust/operations zero-trust-operations",
                "7 menu.zerotrust.bridge /contexa/admin/zero-trust/bridge zero-trust-bridge");
        assertThat(jdbc.queryForObject("SELECT name FROM ctxa_admin_menu WHERE data_page = 'security-monitor'",
                String.class)).isEqualTo("menu.security.events");
    }

    @Test
    @DisplayName("a database that still holds the AI monitor's menus loses them and their roles; a second run changes nothing")
    void theOldMenusGoAndTheSeedRunsAgain() throws Exception {
        Long group = jdbc.queryForObject("SELECT id FROM ctxa_admin_menu WHERE data_page = 'ai-monitor'", Long.class);
        jdbc.update("INSERT INTO ctxa_admin_menu (name, url, icon, parent_id, menu_order, enabled, menu_type, data_page) "
                + "VALUES ('menu.aiMonitor.overview', '/contexa/admin/ai-monitor', '', ?, 1, TRUE, 'CORE', "
                + "'ai-monitor-overview')", group);
        jdbc.update("INSERT INTO ctxa_admin_menu_role (menu_id, role_name) SELECT id, 'ROLE_ADMIN' FROM ctxa_admin_menu "
                + "WHERE data_page = 'ai-monitor-overview'");
        jdbc.update("UPDATE ctxa_admin_menu SET name = 'menu.zerotrust.monitor' WHERE data_page = 'security-monitor'");
        long menusBefore = count("SELECT count(*) FROM ctxa_admin_menu");

        run("META-INF/contexa/db/data-menu.sql");

        assertThat(count("SELECT count(*) FROM ctxa_admin_menu WHERE data_page LIKE 'ai-monitor-%'")).isZero();
        assertThat(count("SELECT count(*) FROM ctxa_admin_menu_role r LEFT JOIN ctxa_admin_menu m ON m.id = r.menu_id "
                + "WHERE m.id IS NULL")).isZero();
        assertThat(jdbc.queryForObject("SELECT name FROM ctxa_admin_menu WHERE data_page = 'security-monitor'",
                String.class)).isEqualTo("menu.security.events");
        assertThat(count("SELECT count(*) FROM ctxa_admin_menu")).isEqualTo(menusBefore - 1);
        List<String> screens = screens();

        run("META-INF/contexa/db/data-menu.sql");

        assertThat(count("SELECT count(*) FROM ctxa_admin_menu")).isEqualTo(menusBefore - 1);
        assertThat(screens()).isEqualTo(screens);
    }

    @Test
    @DisplayName("plan 6-6: the prompt quality group holds the prompt versions, not the releases")
    void thePromptQualityGroupHoldsThePromptVersions() {
        assertThat(jdbc.queryForList("""
                SELECT m.menu_order || ' ' || m.name || ' ' || m.url
                  FROM ctxa_admin_menu m
                  JOIN ctxa_admin_menu g ON g.id = m.parent_id AND g.data_page = 'prompt-quality'
                 WHERE m.data_page = 'prompt-quality-versions'
                """, String.class)).containsExactly("4 menu.pqa.versions /contexa/admin/prompt-quality/versions");
        assertThat(count("SELECT count(*) FROM ctxa_admin_menu WHERE data_page = 'prompt-quality-releases'")).isZero();
    }

    @Test
    @DisplayName("quality plan 3.8: the prompt quality group holds its menus in the order of its screens' menu bar")
    void thePromptQualityGroupHoldsItsMenusInTheOrderOfTheBar() {
        assertThat(promptQualityMenus()).containsExactly(PROMPT_QUALITY_MENUS);
        assertThat(jdbc.queryForObject("SELECT name || ' ' || menu_type FROM ctxa_admin_menu WHERE data_page = "
                + "'prompt-quality' AND parent_id IS NULL", String.class)).isEqualTo("menu.nav.pqa CORE");
    }

    @Test
    @DisplayName("quality plan 3.8: an installation of the earlier menus gets the new ones once, in the new order, its roles kept")
    void anInstallationOfTheEarlierMenusGetsTheNewOnesOnce() throws Exception {
        // An installation seeded before the labelled cases and measure and compare: the sealed prompts before the
        // versions, a role on the versions.
        jdbc.update("DELETE FROM ctxa_admin_menu WHERE data_page IN ('prompt-quality-cases', 'prompt-quality-measure')");
        jdbc.update("UPDATE ctxa_admin_menu SET menu_order = 5 WHERE data_page = 'prompt-quality-versions'");
        jdbc.update("UPDATE ctxa_admin_menu SET menu_order = 4 WHERE data_page = 'prompt-quality-evidence'");
        Long versions = jdbc.queryForObject("SELECT id FROM ctxa_admin_menu WHERE data_page = 'prompt-quality-versions'",
                Long.class);
        jdbc.update("INSERT INTO ctxa_admin_menu_role (menu_id, role_name) VALUES (?, 'ROLE_QUALITY_REVIEWER')", versions);
        long menusBefore = count("SELECT count(*) FROM ctxa_admin_menu");

        run("META-INF/contexa/db/data-menu.sql");

        assertThat(promptQualityMenus()).containsExactly(PROMPT_QUALITY_MENUS);
        assertThat(count("SELECT count(*) FROM ctxa_admin_menu")).isEqualTo(menusBefore + 2);
        assertThat(jdbc.queryForObject("SELECT id FROM ctxa_admin_menu WHERE data_page = 'prompt-quality-versions'",
                Long.class)).isEqualTo(versions);
        assertThat(jdbc.queryForList("SELECT role_name FROM ctxa_admin_menu_role WHERE menu_id = ?", String.class,
                versions)).contains("ROLE_QUALITY_REVIEWER");

        run("META-INF/contexa/db/data-menu.sql");

        assertThat(count("SELECT count(*) FROM ctxa_admin_menu")).isEqualTo(menusBefore + 2);
        assertThat(promptQualityMenus()).containsExactly(PROMPT_QUALITY_MENUS);
        // The database is shared by the tests of this class: the role goes again.
        jdbc.update("DELETE FROM ctxa_admin_menu_role WHERE role_name = 'ROLE_QUALITY_REVIEWER'");
    }

    /** Quality plan 3.8: the five menus of the group in the order of the screens' menu bar. */
    private static final String[] PROMPT_QUALITY_MENUS = {
            "1 menu.pqa.status /contexa/admin/prompt-quality/status prompt-quality-status CORE",
            "2 menu.pqa.cases /contexa/admin/prompt-quality/cases prompt-quality-cases CORE",
            "3 menu.pqa.measure /contexa/admin/prompt-quality/measure prompt-quality-measure CORE",
            "4 menu.pqa.versions /contexa/admin/prompt-quality/versions prompt-quality-versions CORE",
            "5 menu.pqa.evidence /contexa/admin/prompt-quality/evidence prompt-quality-evidence CORE"};

    @Test
    @DisplayName("quality plan 3.6 to 3.8: an installation of the first bundle gets the quality status once and its sealed prompts become the sealed evidence, roles kept")
    void anInstallationOfTheFirstBundleGetsTheStatusAndTheSealedEvidence() throws Exception {
        // An installation seeded by the first bundle: no quality status, the sealed prompts under their own page, a
        // role on them.
        jdbc.update("DELETE FROM ctxa_admin_menu WHERE data_page = 'prompt-quality-status'");
        jdbc.update("UPDATE ctxa_admin_menu SET data_page = 'prompt-inspection-packages',"
                + " name = 'menu.pqa.inspection.packages', url = '/contexa/admin/prompt-inspection/packages'"
                + " WHERE data_page = 'prompt-quality-evidence'");
        Long sealed = jdbc.queryForObject("SELECT id FROM ctxa_admin_menu WHERE data_page = 'prompt-inspection-packages'",
                Long.class);
        jdbc.update("INSERT INTO ctxa_admin_menu_role (menu_id, role_name) VALUES (?, 'ROLE_EVIDENCE_AUDITOR')", sealed);
        long menusBefore = count("SELECT count(*) FROM ctxa_admin_menu");

        run("META-INF/contexa/db/data-menu.sql");

        assertThat(promptQualityMenus()).containsExactly(PROMPT_QUALITY_MENUS);
        assertThat(count("SELECT count(*) FROM ctxa_admin_menu")).isEqualTo(menusBefore + 1);
        assertThat(count("SELECT count(*) FROM ctxa_admin_menu WHERE data_page = 'prompt-inspection-packages'"))
                .isZero();
        assertThat(jdbc.queryForObject("SELECT id FROM ctxa_admin_menu WHERE data_page = 'prompt-quality-evidence'",
                Long.class)).isEqualTo(sealed);
        assertThat(jdbc.queryForList("SELECT role_name FROM ctxa_admin_menu_role WHERE menu_id = ?", String.class,
                sealed)).contains("ROLE_EVIDENCE_AUDITOR");

        run("META-INF/contexa/db/data-menu.sql");

        assertThat(count("SELECT count(*) FROM ctxa_admin_menu")).isEqualTo(menusBefore + 1);
        assertThat(promptQualityMenus()).containsExactly(PROMPT_QUALITY_MENUS);
        // The database is shared by the tests of this class: the role goes again.
        jdbc.update("DELETE FROM ctxa_admin_menu_role WHERE role_name = 'ROLE_EVIDENCE_AUDITOR'");
    }

    private static List<String> promptQualityMenus() {
        return jdbc.queryForList("""
                SELECT m.menu_order || ' ' || m.name || ' ' || m.url || ' ' || m.data_page || ' ' || m.menu_type
                  FROM ctxa_admin_menu m
                  JOIN ctxa_admin_menu g ON g.id = m.parent_id AND g.data_page = 'prompt-quality'
                 WHERE m.enabled
                 ORDER BY m.menu_order
                """, String.class);
    }

    @Test
    @DisplayName("plan 6-6: an installation's releases menu becomes the prompt versions with its roles; a second run changes nothing")
    void theReleasesMenuOfAnInstallationBecomesThePromptVersions() throws Exception {
        // An installation seeded before the version screens: its menu row is the releases', with a role on it.
        jdbc.update("UPDATE ctxa_admin_menu SET data_page = 'prompt-quality-releases', name = 'menu.pqa.releases',"
                + " url = '/contexa/admin/prompt-quality/releases' WHERE data_page = 'prompt-quality-versions'");
        Long id = jdbc.queryForObject("SELECT id FROM ctxa_admin_menu WHERE data_page = 'prompt-quality-releases'",
                Long.class);
        jdbc.update("INSERT INTO ctxa_admin_menu_role (menu_id, role_name) VALUES (?, 'ROLE_AUDITOR')", id);
        long menusBefore = count("SELECT count(*) FROM ctxa_admin_menu");

        run("META-INF/contexa/db/data-menu.sql");

        assertThat(count("SELECT count(*) FROM ctxa_admin_menu WHERE data_page = 'prompt-quality-releases'")).isZero();
        assertThat(jdbc.queryForObject("SELECT id || ' ' || name || ' ' || url FROM ctxa_admin_menu"
                + " WHERE data_page = 'prompt-quality-versions'", String.class))
                .isEqualTo(id + " menu.pqa.versions /contexa/admin/prompt-quality/versions");
        assertThat(jdbc.queryForList("SELECT role_name FROM ctxa_admin_menu_role WHERE menu_id = ?", String.class, id))
                .contains("ROLE_AUDITOR");
        assertThat(count("SELECT count(*) FROM ctxa_admin_menu")).isEqualTo(menusBefore);

        run("META-INF/contexa/db/data-menu.sql");

        assertThat(count("SELECT count(*) FROM ctxa_admin_menu")).isEqualTo(menusBefore);
        assertThat(count("SELECT count(*) FROM ctxa_admin_menu WHERE data_page = 'prompt-quality-versions'")).isEqualTo(1);
    }

    private static List<String> screens() {
        return jdbc.queryForList("""
                SELECT m.menu_order || ' ' || m.name || ' ' || m.url || ' ' || m.data_page
                  FROM ctxa_admin_menu m
                  JOIN ctxa_admin_menu g ON g.id = m.parent_id AND g.data_page = 'ai-monitor'
                 ORDER BY m.menu_order
                """, String.class);
    }

    private static long count(String sql) {
        Long value = jdbc.queryForObject(sql, Long.class);
        return value == null ? 0L : value;
    }

    private static void run(String script) throws Exception {
        String sql = new ClassPathResource(script).getContentAsString(StandardCharsets.UTF_8);
        try (Connection connection = database.dataSource().getConnection();
             Statement statement = connection.createStatement()) {
            statement.setEscapeProcessing(false);
            statement.execute(sql);
        }
    }
}
