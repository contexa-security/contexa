package io.contexa.autoconfigure.compat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

class LegacyPrefixMigratorTest {

    private final LegacyPrefixMigrator migrator = new LegacyPrefixMigrator();

    @Test
    @DisplayName("기존 security.zerotrust.* 키가 contexa.security.zerotrust.* 로 alias 된다")
    void aliasesSecurityZerotrust() {
        MockEnvironment env = new MockEnvironment();
        env.setProperty("security.zerotrust.mode", "ENFORCE");

        migrator.postProcessEnvironment(env, new SpringApplication());

        assertThat(env.getProperty("contexa.security.zerotrust.mode")).isEqualTo("ENFORCE");
        assertThat(env.getProperty("security.zerotrust.mode")).isEqualTo("ENFORCE");
    }

    @Test
    @DisplayName("hcad.* 키가 contexa.hcad.* 로 alias 된다")
    void aliasesHcad() {
        MockEnvironment env = new MockEnvironment();
        env.setProperty("hcad.enabled", "true");
        env.setProperty("hcad.geoip.dbPath", "data/GeoLite2-City.mmdb");

        migrator.postProcessEnvironment(env, new SpringApplication());

        assertThat(env.getProperty("contexa.hcad.enabled")).isEqualTo("true");
        assertThat(env.getProperty("contexa.hcad.geoip.dbPath")).isEqualTo("data/GeoLite2-City.mmdb");
    }

    @Test
    @DisplayName("spring.auth.* 가 contexa.auth.* 로 alias 된다")
    void aliasesSpringAuth() {
        MockEnvironment env = new MockEnvironment();
        env.setProperty("spring.auth.tokenTransportType", "HEADER");

        migrator.postProcessEnvironment(env, new SpringApplication());

        assertThat(env.getProperty("contexa.auth.tokenTransportType")).isEqualTo("HEADER");
    }

    @Test
    @DisplayName("spring.ai.security.tiered.* 가 contexa.security.tiered.* 로 alias 된다 (specific prefix 우선)")
    void aliasesTieredBeforeAiSecurityRoot() {
        MockEnvironment env = new MockEnvironment();
        env.setProperty("spring.ai.security.tiered.layer1.enabled", "true");

        migrator.postProcessEnvironment(env, new SpringApplication());

        assertThat(env.getProperty("contexa.security.tiered.layer1.enabled")).isEqualTo("true");
        // The shorter spring.ai.security. prefix must NOT win for the same key
        assertThat(env.getProperty("contexa.security.tiered.llm.tiered.layer1.enabled")).isNull();
    }

    @Test
    @DisplayName("spring.ai.vectorstore.pgvector.* 가 contexa.vectorstore.pgvector.* 로 alias 된다")
    void aliasesPgVectorStore() {
        MockEnvironment env = new MockEnvironment();
        env.setProperty("spring.ai.vectorstore.pgvector.dimensions", "1536");

        migrator.postProcessEnvironment(env, new SpringApplication());

        assertThat(env.getProperty("contexa.vectorstore.pgvector.dimensions")).isEqualTo("1536");
    }

    @Test
    @DisplayName("이미 신규 prefix 가 정의된 키는 기존 키보다 우선 (alias 가 덮어쓰지 않음)")
    void newPrefixWins() {
        MockEnvironment env = new MockEnvironment();
        env.setProperty("contexa.security.zerotrust.mode", "ENFORCE");
        env.setProperty("security.zerotrust.mode", "SHADOW");

        migrator.postProcessEnvironment(env, new SpringApplication());

        // The MapPropertySource is added with addFirst, so its values appear before
        // the legacy ones. addFirst adds aliases AFTER the existing primary keys
        // so existing contexa.* keys still win.
        assertThat(env.getProperty("contexa.security.zerotrust.mode")).isEqualTo("ENFORCE");
    }

    @Test
    @DisplayName("역방향 alias: contexa.vectorstore.pgvector.* 가 Spring AI 표준 prefix 로도 노출된다")
    void reverseAliasesPgVectorToSpringAi() {
        MockEnvironment env = new MockEnvironment();
        env.setProperty("contexa.vectorstore.pgvector.dimensions", "2048");

        migrator.postProcessEnvironment(env, new SpringApplication());

        assertThat(env.getProperty("spring.ai.vectorstore.pgvector.dimensions")).isEqualTo("2048");
    }

    @Test
    @DisplayName("EXACT_KEY_MAP 매핑: security.mfa.session.storage-type 가 contexa.auth.mfa.session-storage-type 로 alias 된다")
    void aliasesExactKeyMapping() {
        MockEnvironment env = new MockEnvironment();
        env.setProperty("security.mfa.session.storage-type", "redis");

        migrator.postProcessEnvironment(env, new SpringApplication());

        assertThat(env.getProperty("contexa.auth.mfa.session-storage-type")).isEqualTo("redis");
    }

    @Test
    @DisplayName("legacy prefix 가 없을 때 환경에 alias property source 가 추가되지 않는다")
    void noLegacyKeyNoAliasSource() {
        MockEnvironment env = new MockEnvironment();
        env.setProperty("contexa.security.zerotrust.mode", "ENFORCE");

        migrator.postProcessEnvironment(env, new SpringApplication());

        assertThat(env.getPropertySources().contains("contexaLegacyPrefixAliases")).isFalse();
    }
}
