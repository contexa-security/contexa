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
package io.contexa.contexacommon.operating;

import io.contexa.contexacommon.security.bridge.SecurityMode;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.asm.ClassWriter;
import org.springframework.asm.Opcodes;
import org.springframework.context.aot.AbstractAotProcessor;
import org.springframework.mock.env.MockEnvironment;

import static io.contexa.contexacommon.operating.ContexaOperatingProfile.PROP_APPLICATION_DATA;
import static io.contexa.contexacommon.operating.ContexaOperatingProfile.PROP_MODE;
import static io.contexa.contexacommon.operating.ContexaOperatingProfile.PROP_OWNERSHIP;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContexaOperatingProfileTest {

    private static MockEnvironment environment() {
        return new MockEnvironment();
    }

    @Test
    void sandboxMeansTheApplicationKeepsTheSignIn() {
        ContexaOperatingProfile profile = ContexaOperatingProfile.of(SecurityMode.SANDBOX, environment());

        assertThat(profile.mode()).isEqualTo(SecurityMode.SANDBOX);
        assertThat(profile.ownership()).isEqualTo(SecurityOwnershipMode.HOST_OWNED);
    }

    @Test
    void fullMeansContexaOwnsTheSignIn() {
        ContexaOperatingProfile profile = ContexaOperatingProfile.of(SecurityMode.FULL, environment());

        assertThat(profile.ownership()).isEqualTo(SecurityOwnershipMode.CONTEXA_OWNED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"CONTEXA_OWNED", "contexa_owned", "contexa-owned", "contexaOwned", "Contexa-Owned", " CONTEXA_OWNED "})
    void everySpellingSpringAcceptsMeansTheSameOwnership(String spelling) {
        ContexaOperatingProfile profile = ContexaOperatingProfile.of(SecurityMode.FULL, environment().withProperty(PROP_OWNERSHIP, spelling));

        assertThat(profile.ownership()).isEqualTo(SecurityOwnershipMode.CONTEXA_OWNED);
    }

    @Test
    void aValueThatIsNoOwnershipIsRefusedAndTheAnswerNamesTheChoices() {
        assertThatThrownBy(() -> ContexaOperatingProfile.of(SecurityMode.SANDBOX, environment().withProperty(PROP_OWNERSHIP, "NOBODY")))
                .isInstanceOf(ContexaOperatingProfileException.class)
                .hasMessageContaining("contexa.bridge.ownership=NOBODY")
                .hasMessageContaining("HOST_OWNED")
                .hasMessageContaining("CONTEXA_OWNED");
    }

    @Test
    void aFullApplicationThatKeepsItsSignInIsRefusedWithWhatToChange() {
        assertThatThrownBy(() -> ContexaOperatingProfile.of(SecurityMode.FULL, environment().withProperty(PROP_OWNERSHIP, "HOST_OWNED")))
                .isInstanceOfSatisfying(ContexaOperatingProfileException.class, refused -> {
                    assertThat(refused.getMessage()).contains("mode = FULL").contains("HOST_OWNED");
                    assertThat(refused.action()).contains("contexa.bridge.ownership").contains("@EnableAISecurity");
                });
    }

    @Test
    void aSandboxApplicationThatGivesContexaItsSignInIsRefusedWithWhatToChange() {
        assertThatThrownBy(() -> ContexaOperatingProfile.of(SecurityMode.SANDBOX, environment().withProperty(PROP_OWNERSHIP, "contexa-owned")))
                .isInstanceOfSatisfying(ContexaOperatingProfileException.class, refused -> {
                    assertThat(refused.getMessage()).contains("SANDBOX").contains("CONTEXA_OWNED");
                    assertThat(refused.action()).contains("mode = FULL");
                });
    }

    @Test
    void anOwnershipThatRepeatsTheModeIsFine() {
        assertThat(ContexaOperatingProfile.of(SecurityMode.FULL, environment().withProperty(PROP_OWNERSHIP, "CONTEXA_OWNED")).ownership())
                .isEqualTo(SecurityOwnershipMode.CONTEXA_OWNED);
        assertThat(ContexaOperatingProfile.of(SecurityMode.SANDBOX, environment().withProperty(PROP_OWNERSHIP, "HOST_OWNED")).ownership())
                .isEqualTo(SecurityOwnershipMode.HOST_OWNED);
    }

    @Test
    void withoutADeclaredModeTheOwnershipStandsAlone() {
        ContexaOperatingProfile profile = ContexaOperatingProfile.resolve(environment().withProperty(PROP_OWNERSHIP, "CONTEXA_OWNED"));

        assertThat(profile.ownership()).isEqualTo(SecurityOwnershipMode.CONTEXA_OWNED);
        assertThat(profile.mode()).isEqualTo(SecurityMode.FULL);
    }

    @Test
    void resolveReadsTheModeTheAnnotationPublished() {
        ContexaOperatingProfile profile = ContexaOperatingProfile.resolve(environment().withProperty(PROP_MODE, "FULL"));

        assertThat(profile.ownership()).isEqualTo(SecurityOwnershipMode.CONTEXA_OWNED);
    }

    @Test
    void nothingDeclaredIsTheDefaultOfAnExistingApplication() {
        ContexaOperatingProfile profile = ContexaOperatingProfile.resolve(environment());

        assertThat(profile.mode()).isEqualTo(SecurityMode.SANDBOX);
        assertThat(profile.ownership()).isEqualTo(SecurityOwnershipMode.HOST_OWNED);
    }

    @Test
    void aModeThatDoesNotExistIsRefused() {
        assertThatThrownBy(() -> ContexaOperatingProfile.resolve(environment().withProperty(PROP_MODE, "PARTIAL")))
                .isInstanceOf(ContexaOperatingProfileException.class)
                .hasMessageContaining("contexa.ai.security.mode=PARTIAL");
    }

    @Test
    void anExistingApplicationDoesNotHandItsDataToContexa() {
        assertThat(ContexaOperatingProfile.of(SecurityMode.SANDBOX, environment()).contexaOwnsApplicationData()).isFalse();
    }

    @Test
    void aNewApplicationWithoutADatabaseOfItsOwnUsesContexas() {
        assertThat(ContexaOperatingProfile.of(SecurityMode.FULL, environment()).contexaOwnsApplicationData()).isTrue();
    }

    @Test
    void aFullApplicationWithItsOwnDatabaseKeepsIt() {
        ContexaOperatingProfile profile = ContexaOperatingProfile.of(SecurityMode.FULL, environment()
                .withProperty("spring.datasource.url", "jdbc:postgresql://db/application")
                .withProperty("contexa.datasource.url", "jdbc:postgresql://db/contexa"));

        assertThat(profile.contexaOwnsApplicationData()).isFalse();
    }

    @Test
    void aFullApplicationPointedAtContexasOwnDatabaseLosesNothing() {
        ContexaOperatingProfile profile = ContexaOperatingProfile.of(SecurityMode.FULL, environment()
                .withProperty("spring.datasource.url", " jdbc:postgresql://db/contexa ")
                .withProperty("contexa.datasource.url", "jdbc:postgresql://db/contexa"));

        assertThat(profile.contexaOwnsApplicationData()).isTrue();
    }

    @Test
    void aDeclaredDatabaseThatIsNotUsedIsNoSecret() {
        ContexaOperatingProfile profile = ContexaOperatingProfile.of(SecurityMode.SANDBOX, environment()
                .withProperty(PROP_APPLICATION_DATA, "true")
                .withProperty("spring.datasource.url", "jdbc:h2:mem:application")
                .withProperty("contexa.datasource.url", "jdbc:postgresql://db/contexa"));

        assertThat(profile.contexaOwnsApplicationData()).isTrue();
        assertThat(profile.declaredDatabaseUnused()).isTrue();
    }

    @Test
    void withoutADatabaseOfItsOwnNothingGoesUnused() {
        assertThat(ContexaOperatingProfile.of(SecurityMode.FULL, environment()).declaredDatabaseUnused()).isFalse();
    }

    @Test
    void whatTheApplicationDeclaresAboutItsDataAlwaysStands() {
        assertThat(ContexaOperatingProfile.of(SecurityMode.SANDBOX, environment().withProperty(PROP_APPLICATION_DATA, "true")).contexaOwnsApplicationData()).isTrue();
        assertThat(ContexaOperatingProfile.of(SecurityMode.FULL, environment().withProperty(PROP_APPLICATION_DATA, "false")).contexaOwnsApplicationData()).isFalse();
    }

    @Test
    void theDistributedModeWithoutTheRedisClientSaysWhatToDo() {
        MockEnvironment environment = new MockEnvironment().withProperty("contexa.infrastructure.mode", "distributed");
        ClassLoader withoutRedis = new ClassLoader(null) {
        };

        assertThatThrownBy(() -> ContexaOperatingProfile.refuseDistributedWithoutRedis(environment, withoutRedis))
                .isInstanceOfSatisfying(ContexaOperatingProfileException.class,
                        e -> assertThat(e.action()).contains("spring-boot-starter-data-redis"));
    }

    /** PR-71: the library the message names brings a JCache provider, so the message says what an application with JCache sets. */
    @Test
    void theAdviceToAddRedissonSaysWhatItDoesToAnApplicationsJCache() {
        MockEnvironment environment = new MockEnvironment().withProperty("contexa.infrastructure.mode", "distributed");

        assertThatThrownBy(() -> ContexaOperatingProfile.refuseDistributedWithoutRedis(environment, new ClassLoader(null) {
        })).isInstanceOfSatisfying(ContexaOperatingProfileException.class,
                e -> assertThat(e.action()).contains("org.redisson:redisson").contains("JCache").contains("spring.cache.type=caffeine"));
    }

    /** A message that does not tell anyone to add Redisson has nothing to say about it. */
    @Test
    void anAdviceWithoutRedissonDoesNotMentionTheCache() {
        MockEnvironment environment = new MockEnvironment().withProperty("contexa.infrastructure.mode", "distributed");
        ClassLoader withRedisson = new ClassLoader(null) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                if (!name.equals("org.redisson.api.RedissonClient")) {
                    throw new ClassNotFoundException(name);
                }
                ClassWriter writer = new ClassWriter(0);
                writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT,
                        name.replace('.', '/'), null, "java/lang/Object", null);
                byte[] redissonClient = writer.toByteArray();
                return defineClass(name, redissonClient, 0, redissonClient.length);
            }
        };

        assertThatThrownBy(() -> ContexaOperatingProfile.refuseDistributedWithoutRedis(environment, withRedisson))
                .isInstanceOfSatisfying(ContexaOperatingProfileException.class,
                        e -> assertThat(e.action()).doesNotContain("spring.cache.type"));
    }

    @Test
    void theStandaloneModeNeedsNoRedisClient() {
        ContexaOperatingProfile.refuseDistributedWithoutRedis(new MockEnvironment(), new ClassLoader(null) {
        });
    }

    /** The starter does not bring Spring Security, so that adding it alone changes nothing: the decision to apply security is the application's. */
    @Test
    void theAnnotationWithoutSpringSecuritySaysWhatToAdd() {
        assertThatThrownBy(() -> ContexaOperatingProfile.refuseWithoutSpringSecurity(new ClassLoader(null) {
        })).isInstanceOfSatisfying(ContexaOperatingProfileException.class,
                e -> assertThat(e.action()).contains("spring-boot-starter-security"));
    }

    /** PR-172: an application on Spring Boot 4 was refused with a stack trace; it is told why and what to do. */
    @Test
    void springBoot4IsRefusedWithWhatToDo() {
        assertThatThrownBy(() -> ContexaOperatingProfile.refuseSpringBoot4("4.1.2"))
                .isInstanceOfSatisfying(ContexaOperatingProfileException.class, refused -> {
                    assertThat(refused.getMessage()).contains("Spring Boot 4.1.2");
                    assertThat(refused.action()).contains("Spring Boot 3.x");
                });
        ContexaOperatingProfile.refuseSpringBoot4("3.5.4");
        ContexaOperatingProfile.refuseSpringBoot4(null);
    }

    /** PR-172: an application that leaves out spring-boot-starter-web ended on NoClassDefFoundError: jakarta/servlet/Filter. */
    @Test
    void anApplicationWithoutTheServletApiIsToldWhatToAdd() {
        assertThatThrownBy(() -> ContexaOperatingProfile.refuseWithoutServletApi(new ClassLoader(null) {
        })).isInstanceOfSatisfying(ContexaOperatingProfileException.class,
                e -> assertThat(e.action()).contains("spring-boot-starter-web"));
        ContexaOperatingProfile.refuseWithoutServletApi(getClass().getClassLoader());
    }

    /**
     * PR-175: a build that runs Spring AOT processing ended on a bean of Contexa's that cannot be written as code, which
     * names neither Contexa nor what to do. Nothing analyses a failure there, so the reason carries what to do as well.
     */
    @Test
    void aBuildThatRunsAotProcessingIsToldInOneLineWhatToDo() {
        duringAotProcessing("true", () -> assertThatThrownBy(ContexaOperatingProfile::refuseAotProcessing)
                .isInstanceOfSatisfying(ContexaOperatingProfileException.class, refused -> {
                    assertThat(refused.getMessage()).isEqualTo("Contexa does not support Spring AOT processing or native"
                            + " images, and this build runs AOT processing on an application with @EnableAISecurity:"
                            + " build it without AOT processing, or remove @EnableAISecurity.");
                    assertThat(refused.getMessage()).doesNotContain("\n");
                    assertThat(refused.action()).isEqualTo("Build this application without AOT processing and without a"
                            + " native image, or remove @EnableAISecurity.");
                }));
    }

    @Test
    void anApplicationThatStartsIsNotInAotProcessing() {
        duringAotProcessing(null, ContexaOperatingProfile::refuseAotProcessing);
        duringAotProcessing("false", ContexaOperatingProfile::refuseAotProcessing);
    }

    /** The property Spring sets for as long as it processes an application ahead of time, and clears after. */
    private static void duringAotProcessing(String value, Runnable build) {
        String before = System.getProperty(AbstractAotProcessor.AOT_PROCESSING);
        try {
            if (value != null) {
                System.setProperty(AbstractAotProcessor.AOT_PROCESSING, value);
            } else {
                System.clearProperty(AbstractAotProcessor.AOT_PROCESSING);
            }
            build.run();
        } finally {
            if (before != null) {
                System.setProperty(AbstractAotProcessor.AOT_PROCESSING, before);
            } else {
                System.clearProperty(AbstractAotProcessor.AOT_PROCESSING);
            }
        }
    }
}
