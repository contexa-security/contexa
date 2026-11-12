/* Copyright 2026 The Contexa Project */
package io.contexa.contexacommon.annotation;

import io.contexa.contexacommon.operating.ContexaOperatingProfileException;
import io.contexa.contexacommon.security.bridge.AuthObjectLocation;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.context.aot.AbstractAotProcessor;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

import java.util.Map;
import org.springframework.core.type.AnnotationMetadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiSecurityImportSelectorTest {

    @Test
    void shouldDefaultToSandboxModeInContextEnvironment() {
        StandardEnvironment environment = select(DefaultSandboxApplication.class);
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_MODE))
                .isEqualTo(SecurityMode.SANDBOX.name());
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_LOCATION))
                .isEqualTo(AuthObjectLocation.AUTO.name());
        assertThat(System.getProperty(AiSecurityImportSelector.PROP_MODE)).isNull();
    }

    /** Contexa's values were added first, so an operator's environment could not change what the code declared. */
    @Test
    void whatAnOperatorSetsOutranksWhatTheCodeDeclares() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("operator", Map.of(
                AiSecurityImportSelector.PROP_MODE, "full",
                AiSecurityImportSelector.PROP_AUTH_OBJECT_ATTRIBUTE, "operatorUser")));
        AiSecurityImportSelector selector = new AiSecurityImportSelector();
        selector.setEnvironment(environment);

        selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class));

        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP))
                .as("the ownership follows the mode the operator set").isEqualTo(SecurityOwnershipMode.CONTEXA_OWNED.name());
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_ATTRIBUTE)).isEqualTo("operatorUser");
    }

    /** Contexa's enforcement is servlet filters: on a reactive server nothing would be enforced and nothing would say so. */
    @Test
    void anApplicationThatChoseTheReactiveStackIsToldInsteadOfLeftUnprotected() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("application",
                Map.of("spring.main.web-application-type", "reactive")));
        AiSecurityImportSelector selector = new AiSecurityImportSelector();
        selector.setEnvironment(environment);

        assertThatThrownBy(() -> selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class)))
                .isInstanceOf(ContexaOperatingProfileException.class)
                .hasMessageContaining("reactive");
    }

    /** A bean of the distributed mode subscribes to Redis at start, so that a Redis that was down stopped the application. */
    @Test
    void anApplicationThatKeepsItsSignInStartsWithContexaOffWhenRedisIsDown() {
        AiSecurityImportSelector selector = new AiSecurityImportSelector(environment -> null, environment -> "127.0.0.1:1 refused");
        selector.setEnvironment(new StandardEnvironment());

        assertThat(selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class))).isEmpty();
    }

    /** Every part of Contexa reads the engine's decisions: without it the start ended on a bean nobody could explain. */
    @ParameterizedTest
    @ValueSource(strings = {"false", "FALSE", "no", "off", "0", ""})
    void anApplicationThatKeepsItsSignInStartsWithContexaOffWithoutTheEngine(String value) {
        StandardEnvironment environment = withEngineSetting(value);
        AiSecurityImportSelector selector = new AiSecurityImportSelector(unreachable -> null, unreachable -> null);
        selector.setEnvironment(environment);

        assertThat(selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class))).isEmpty();
        assertThat(environment.getPropertySources().contains(AiSecurityImportSelector.ACTIVATION_SOURCE))
                .as("nothing of Contexa is active").isFalse();
    }

    @ParameterizedTest
    @ValueSource(classes = {FullModeApplication.class, DefaultSandboxApplication.class})
    void anApplicationWhoseSignInContexaOwnsIsToldWhyItDoesNotStartWithoutTheEngine(Class<?> application) {
        StandardEnvironment environment = withEngineSetting("false");
        if (application == DefaultSandboxApplication.class) {
            environment.getPropertySources().addFirst(new MapPropertySource("operator",
                    Map.of(AiSecurityImportSelector.PROP_MODE, "FULL")));
        }
        AiSecurityImportSelector selector = new AiSecurityImportSelector(unreachable -> null, unreachable -> null);
        selector.setEnvironment(environment);

        assertThatThrownBy(() -> selector.selectImports(AnnotationMetadata.introspect(application)))
                .isInstanceOf(ContexaOperatingProfileException.class)
                .hasMessageContaining("contexa.autonomous.enabled=false")
                .hasMessageContaining("nobody could sign in")
                .satisfies(refusal -> assertThat(((ContexaOperatingProfileException) refusal).action())
                        .contains("contexa.security.zerotrust.mode=DISABLED"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "TRUE", "True"})
    void theEngineSwitchedOnStartsContexaAsBefore(String value) {
        StandardEnvironment environment = withEngineSetting(value);
        AiSecurityImportSelector selector = new AiSecurityImportSelector(unreachable -> null, unreachable -> null);
        selector.setEnvironment(environment);

        assertThat(selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class))).isNotEmpty();
    }

    private static StandardEnvironment withEngineSetting(String value) {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("application",
                Map.of("contexa.autonomous.enabled", value)));
        return environment;
    }

    @Test
    void anApplicationWhoseSignInContexaOwnsDoesNotAskRedisAndFailsAsItAlwaysDid() {
        AiSecurityImportSelector selector = new AiSecurityImportSelector(environment -> null, environment -> "127.0.0.1:1 refused");
        selector.setEnvironment(new StandardEnvironment());

        assertThat(selector.selectImports(AnnotationMetadata.introspect(FullModeApplication.class))).isNotEmpty();
    }

    @Test
    void shouldPropagateFullModeWhenDeclared() {
        StandardEnvironment environment = select(FullModeApplication.class);
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_MODE))
                .isEqualTo(SecurityMode.FULL.name());
    }

    @Test
    void shouldDefaultSandboxToHostOwned() {
        StandardEnvironment environment = select(DefaultSandboxApplication.class);
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP))
                .isEqualTo(SecurityOwnershipMode.HOST_OWNED.name());
        assertThat(environment.getProperty(
                AiSecurityImportSelector.PROP_CONTEXA_OWNED_APPLICATION, Boolean.class))
                .isFalse();
    }

    @Test
    void shouldDefaultFullModeToContexaOwned() {
        StandardEnvironment environment = select(FullModeApplication.class);
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP))
                .isEqualTo(SecurityOwnershipMode.CONTEXA_OWNED.name());
        assertThat(environment.getProperty(
                AiSecurityImportSelector.PROP_CONTEXA_OWNED_APPLICATION, Boolean.class))
                .isTrue();
    }

    @Test
    void aFullApplicationThatSaysItKeepsItsSignInDoesNotStart() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("explicitOwnership",
                Map.of(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP, SecurityOwnershipMode.HOST_OWNED.name())));
        AiSecurityImportSelector selector = new AiSecurityImportSelector();
        selector.setEnvironment(environment);

        assertThatThrownBy(() -> selector.selectImports(AnnotationMetadata.introspect(FullModeApplication.class)))
                .isInstanceOf(ContexaOperatingProfileException.class);
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_MODE)).isNull();
    }

    @Test
    void aSandboxApplicationThatGivesContexaItsSignInDoesNotStart() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("explicitOwnership",
                Map.of(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP, SecurityOwnershipMode.CONTEXA_OWNED.name())));
        AiSecurityImportSelector selector = new AiSecurityImportSelector();
        selector.setEnvironment(environment);

        assertThatThrownBy(() -> selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class)))
                .isInstanceOf(ContexaOperatingProfileException.class);
    }

    @Test
    void aSandboxApplicationWithoutADatabaseOfItsOwnKeepsSayingSo() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("explicitData",
                Map.of(AiSecurityImportSelector.PROP_CONTEXA_OWNED_APPLICATION, true)));
        AiSecurityImportSelector selector = new AiSecurityImportSelector(unused -> null);
        selector.setEnvironment(environment);

        selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class));

        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP)).isEqualTo(SecurityOwnershipMode.HOST_OWNED.name());
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_CONTEXA_OWNED_APPLICATION, Boolean.class)).isTrue();
    }

    @Test
    void whatIsPublishedIsTheOneSpellingWhateverTheApplicationWrote() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("relaxedOwnership",
                Map.of(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP, "contexa-owned")));
        AiSecurityImportSelector selector = new AiSecurityImportSelector();
        selector.setEnvironment(environment);

        selector.selectImports(AnnotationMetadata.introspect(FullModeApplication.class));

        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP)).isEqualTo(SecurityOwnershipMode.CONTEXA_OWNED.name());
    }

    @Test
    void shouldPropagateAuthObjectHintsWhenDeclared() {
        StandardEnvironment environment = select(SessionHintApplication.class);
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_LOCATION))
                .isEqualTo(AuthObjectLocation.SESSION.name());
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_ATTRIBUTE))
                .isEqualTo("legacyUser");
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_AUTH_OBJECT_TYPE))
                .isEqualTo(LegacyUser.class.getName());
    }

    @Test
    void shouldNotLeakActivationAcrossContexts() {
        StandardEnvironment full = select(FullModeApplication.class);
        StandardEnvironment untouched = new StandardEnvironment();
        assertThat(full.getProperty(AiSecurityImportSelector.PROP_MODE)).isEqualTo("FULL");
        assertThat(untouched.getProperty(AiSecurityImportSelector.PROP_MODE)).isNull();
    }

    @Test
    void anApplicationThatKeepsItsSignInStartsWithContexaOffWhenTheDatabaseIsDown() {
        StandardEnvironment environment = new StandardEnvironment();
        AiSecurityImportSelector selector = new AiSecurityImportSelector(unused -> "connection refused");
        selector.setEnvironment(environment);

        assertThat(selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class))).isEmpty();
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_MODE)).isNull();
    }

    /** Spring Boot's JPA would otherwise start on Contexa's database as the application's own, and it is down. */
    @Test
    void anApplicationWithoutADatabaseOfItsOwnDoesNotTakeTheOneThatIsDown() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("explicitData",
                Map.of(AiSecurityImportSelector.PROP_CONTEXA_OWNED_APPLICATION, true)));
        AiSecurityImportSelector selector = new AiSecurityImportSelector(unused -> "connection refused");
        selector.setEnvironment(environment);

        selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class));

        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_CONTEXA_OWNED_APPLICATION, Boolean.class)).isFalse();
    }

    /** With Redis down the database answers: the application keeps the one it said it uses. */
    @Test
    void anApplicationWithoutADatabaseOfItsOwnKeepsTheOneThatAnswersWhenRedisIsDown() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("explicitData",
                Map.of(AiSecurityImportSelector.PROP_CONTEXA_OWNED_APPLICATION, true)));
        AiSecurityImportSelector selector = new AiSecurityImportSelector(unused -> null, unused -> "127.0.0.1:1 refused");
        selector.setEnvironment(environment);

        selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class));

        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_CONTEXA_OWNED_APPLICATION, Boolean.class)).isTrue();
    }

    /** The application's own settings name the mode: nothing of it may read as Contexa being on. */
    @Test
    void aModeInTheSettingsPublishesNothingWhenTheDatabaseIsDown() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("operator",
                Map.of(AiSecurityImportSelector.PROP_MODE, SecurityMode.SANDBOX.name())));
        AiSecurityImportSelector selector = new AiSecurityImportSelector(unused -> "connection refused");
        selector.setEnvironment(environment);

        assertThat(selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class))).isEmpty();
        assertThat(environment.getPropertySources().contains("contexaAiSecurityAnnotation")).isFalse();
    }

    @Test
    void anApplicationWhoseSignInContexaOwnsDoesNotAskTheDatabaseAndFailsAsItAlwaysDid() {
        StandardEnvironment environment = new StandardEnvironment();
        AiSecurityImportSelector selector = new AiSecurityImportSelector(unused -> {
            throw new AssertionError("the database must not be asked");
        });
        selector.setEnvironment(environment);

        assertThat(selector.selectImports(AnnotationMetadata.introspect(FullModeApplication.class))).isNotEmpty();
    }

    @Test
    void theOwnershipIsReadAsTheBridgeReadsItHoweverItIsWritten() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("explicitOwnership",
                Map.of(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP, "contexa-owned")));
        AiSecurityImportSelector selector = new AiSecurityImportSelector(unused -> "connection refused");
        selector.setEnvironment(environment);

        assertThat(selector.selectImports(AnnotationMetadata.introspect(FullModeApplication.class))).isNotEmpty();
    }

    @Test
    void aDatabaseThatAnswersChangesNothing() {
        StandardEnvironment environment = new StandardEnvironment();
        AiSecurityImportSelector selector = new AiSecurityImportSelector(unused -> null);
        selector.setEnvironment(environment);

        assertThat(selector.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class))).isNotEmpty();
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_MODE)).isEqualTo(SecurityMode.SANDBOX.name());
    }

    @Test
    void shouldSkipImportWhenContexaIsExplicitlyDisabled() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("contexaDisabled",
                Map.of(AiSecurityImportSelector.PROP_ENABLED, false)));
        AiSecurityImportSelector selector = new AiSecurityImportSelector();
        selector.setEnvironment(environment);

        String[] imports = selector.selectImports(AnnotationMetadata.introspect(FullModeApplication.class));

        assertThat(imports).isEmpty();
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_MODE)).isNull();
        assertThat(environment.getProperty(AiSecurityImportSelector.PROP_BRIDGE_OWNERSHIP)).isNull();
    }

    /**
     * PR-175: Contexa's beans cannot be written as code, so a build that runs Spring AOT processing ended on one of them
     * without a word about Contexa. It is refused before anything of Contexa is brought or asked.
     */
    @ParameterizedTest
    @ValueSource(classes = {DefaultSandboxApplication.class, FullModeApplication.class})
    void aBuildThatRunsAotProcessingIsToldThatContexaDoesNotSupportIt(Class<?> application) {
        StandardEnvironment environment = new StandardEnvironment();
        AiSecurityImportSelector selector = new AiSecurityImportSelector(unused -> {
            throw new AssertionError("the database must not be asked");
        }, unused -> {
            throw new AssertionError("Redis must not be asked");
        });
        selector.setEnvironment(environment);

        duringAotProcessing(() -> assertThatThrownBy(() -> selector.selectImports(AnnotationMetadata.introspect(application)))
                .isInstanceOf(ContexaOperatingProfileException.class)
                .hasMessageContaining("Contexa does not support Spring AOT processing")
                .hasMessageContaining("remove @EnableAISecurity"));

        assertThat(environment.getPropertySources().contains(AiSecurityImportSelector.ACTIVATION_SOURCE))
                .as("nothing of Contexa is active").isFalse();
    }

    /** Contexa left out of the code a build generates stays out of the application for good, and nothing would say so. */
    @Test
    void aBuildThatRunsAotProcessingIsNotLeftWithContexaOffWhereAStartWouldBe() {
        AiSecurityImportSelector withoutTheEngine = new AiSecurityImportSelector(unreachable -> null, unreachable -> null);
        withoutTheEngine.setEnvironment(withEngineSetting("false"));
        AiSecurityImportSelector withoutTheDatabase = new AiSecurityImportSelector(unused -> "connection refused");
        withoutTheDatabase.setEnvironment(new StandardEnvironment());

        duringAotProcessing(() -> {
            assertThatThrownBy(() -> withoutTheEngine.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class)))
                    .isInstanceOf(ContexaOperatingProfileException.class)
                    .hasMessageContaining("Spring AOT processing");
            assertThatThrownBy(() -> withoutTheDatabase.selectImports(AnnotationMetadata.introspect(DefaultSandboxApplication.class)))
                    .isInstanceOf(ContexaOperatingProfileException.class)
                    .hasMessageContaining("Spring AOT processing");
        });
    }

    /** An application that switched Contexa off is built as any other. */
    @Test
    void aBuildWithContexaSwitchedOffRunsAotProcessingAsAnyOther() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("contexaDisabled",
                Map.of(AiSecurityImportSelector.PROP_ENABLED, false)));
        AiSecurityImportSelector selector = new AiSecurityImportSelector();
        selector.setEnvironment(environment);

        duringAotProcessing(() ->
                assertThat(selector.selectImports(AnnotationMetadata.introspect(FullModeApplication.class))).isEmpty());
    }

    /** Spring sets the property for as long as it processes an application ahead of time, and clears it after. */
    private static void duringAotProcessing(Runnable build) {
        String before = System.getProperty(AbstractAotProcessor.AOT_PROCESSING);
        System.setProperty(AbstractAotProcessor.AOT_PROCESSING, "true");
        try {
            build.run();
        } finally {
            if (before != null) {
                System.setProperty(AbstractAotProcessor.AOT_PROCESSING, before);
            } else {
                System.clearProperty(AbstractAotProcessor.AOT_PROCESSING);
            }
        }
    }

    private StandardEnvironment select(Class<?> applicationClass) {
        StandardEnvironment environment = new StandardEnvironment();
        AiSecurityImportSelector selector = new AiSecurityImportSelector();
        selector.setEnvironment(environment);
        selector.selectImports(AnnotationMetadata.introspect(applicationClass));
        return environment;
    }

    @EnableAISecurity
    static class DefaultSandboxApplication {
    }

    @EnableAISecurity(mode = SecurityMode.FULL)
    static class FullModeApplication {
    }

    @EnableAISecurity(authObjectLocation = AuthObjectLocation.SESSION,
            authObjectAttribute = "legacyUser", authObjectType = LegacyUser.class)
    static class SessionHintApplication {
    }

    static class LegacyUser {
    }
}
