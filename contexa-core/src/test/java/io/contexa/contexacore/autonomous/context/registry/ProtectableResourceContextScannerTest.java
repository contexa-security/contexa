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
package io.contexa.contexacore.autonomous.context.registry;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.annotation.ResourceImportance;
import io.contexa.contexacore.autonomous.context.model.ResourceContextDescriptor;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;

import java.lang.reflect.Proxy;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** The startup scan puts every {@code @Protectable} method in the resource registry (W2-11). */
class ProtectableResourceContextScannerTest {

    @Test
    void aProtectedMethodIsRegisteredWithWhatItsAnnotationDeclares() {
        InMemoryResourceContextRegistry registry = scanned(new Operations());

        ResourceContextDescriptor export = registry.findByResourceId(Operations.class.getName() + "#exportDocuments")
                .orElseThrow();
        assertThat(export.resourceCategory()).isEqualTo("PROJECT_DOCUMENTS");
        assertThat(export.sensitivity()).isEqualTo("RESTRICTED");
        assertThat(export.allowedActionFamilies()).containsExactly("EXPORT");
        assertThat(export.privileged()).isNull();
        assertThat(export.exportSensitive()).isTrue();
    }

    @Test
    void aMethodThatDeclaresNothingIsRegisteredAndStatesNothing() {
        InMemoryResourceContextRegistry registry = scanned(new Operations());

        ResourceContextDescriptor read = registry.findByResourceId(Operations.class.getName() + "#readDocument")
                .orElseThrow();
        assertThat(read.resourceCategory()).isNull();
        assertThat(read.sensitivity()).isNull();
        assertThat(read.allowedActionFamilies()).isEmpty();
        assertThat(read.privileged()).isNull();
        assertThat(read.exportSensitive()).isNull();
        assertThat(registry.findByResourceId(Operations.class.getName() + "#health")).isEmpty();
    }

    @Test
    void aClassLevelAnnotationProtectsEveryPublicMethod() {
        InMemoryResourceContextRegistry registry = scanned(new AdminOperations());

        assertThat(registry.findByResourceId(AdminOperations.class.getName() + "#grantRole").orElseThrow().privileged())
                .isTrue();
        assertThat(registry.findByResourceId(AdminOperations.class.getName() + "#revokeRole")).isPresent();
        assertThat(registry.findByResourceId(Object.class.getName() + "#toString")).isEmpty();
    }

    @Test
    void anInterfaceProxyIsRegisteredUnderTheInterfaceMethodItCalls() {
        CustomerLookup proxy = (CustomerLookup) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[] {CustomerLookup.class}, (target, method, args) -> null);

        InMemoryResourceContextRegistry registry = scanned(proxy);

        assertThat(registry.findByResourceId(CustomerLookup.class.getName() + "#readCustomer").orElseThrow()
                .resourceCategory()).isEqualTo("CUSTOMER_RECORDS");
    }

    /** RL-14, IM-01: a method that says nothing about its importance is unspecified, and the annotation defaults so. */
    @Test
    void aMethodThatDeclaresNoImportanceIsUnspecified() throws Exception {
        assertThat(Operations.class.getMethod("readDocument").getAnnotation(Protectable.class).importance())
                .isEqualTo(ResourceImportance.UNSPECIFIED);

        InMemoryResourceContextRegistry registry = scanned(new Operations());

        assertThat(registry.findByResourceId(Operations.class.getName() + "#readDocument").orElseThrow().importance())
                .isEqualTo(ResourceImportance.UNSPECIFIED);
        assertThat(registry.findByResourceId(Operations.class.getName() + "#exportDocuments").orElseThrow()
                .importance()).isEqualTo(ResourceImportance.UNSPECIFIED);
    }

    /** RL-14, IM-10: the descriptor carries the importance the annotation declares, on a method, a class and a proxy. */
    @Test
    void theDescriptorCarriesTheImportanceTheAnnotationDeclares() {
        InMemoryResourceContextRegistry registry = scanned(new ImportanceOperations());

        assertThat(registry.findByResourceId(ImportanceOperations.class.getName() + "#listTitles").orElseThrow()
                .importance()).isEqualTo(ResourceImportance.NON_SENSITIVE);
        assertThat(registry.findByResourceId(ImportanceOperations.class.getName() + "#exportAll").orElseThrow()
                .importance()).isEqualTo(ResourceImportance.SENSITIVE);
        assertThat(registry.findByResourceId(ImportanceOperations.class.getName() + "#readRecord").orElseThrow()
                .importance()).isEqualTo(ResourceImportance.SENSITIVE);

        InMemoryResourceContextRegistry classLevel = scanned(new SensitiveClass());
        assertThat(classLevel.findByResourceId(SensitiveClass.class.getName() + "#readRecord").orElseThrow()
                .importance()).isEqualTo(ResourceImportance.SENSITIVE);
        // IM-09: the method's own declaration is the one the publisher finds, so it wins over the class's.
        assertThat(classLevel.findByResourceId(SensitiveClass.class.getName() + "#listTitles").orElseThrow()
                .importance()).isEqualTo(ResourceImportance.NON_SENSITIVE);

        SensitiveLookup proxy = (SensitiveLookup) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[] {SensitiveLookup.class}, (target, method, args) -> null);
        assertThat(scanned(proxy).findByResourceId(SensitiveLookup.class.getName() + "#readCustomer").orElseThrow()
                .importance()).isEqualTo(ResourceImportance.SENSITIVE);
    }

    /** A descriptor built the old way, without an importance, states none. */
    @Test
    void aDescriptorBuiltWithoutAnImportanceStatesNone() {
        ResourceContextDescriptor descriptor = new ResourceContextDescriptor("resource", null, null, "CATEGORY",
                "INTERNAL", List.of(), List.of("READ"), null, null);

        assertThat(descriptor.importance()).isEqualTo(ResourceImportance.UNSPECIFIED);
    }

    @Test
    void aDescriptorTheHostDefinesReplacesTheScannedOne() {
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerSingleton("operations", new Operations());
        beanFactory.registerSingleton("exportDescriptor", new ResourceContextDescriptor(
                Operations.class.getName() + "#exportDocuments", "DOCUMENT", "Project export", "TRANSFER_PACKAGES",
                "CONFIDENTIAL", List.of(), List.of("EXPORT"), null, true));
        InMemoryResourceContextRegistry registry = new InMemoryResourceContextRegistry();

        new ProtectableResourceContextScanner(beanFactory, registry).afterSingletonsInstantiated();

        ResourceContextDescriptor export = registry.findByResourceId(Operations.class.getName() + "#exportDocuments")
                .orElseThrow();
        assertThat(export.resourceCategory()).isEqualTo("TRANSFER_PACKAGES");
        assertThat(export.businessLabel()).isEqualTo("Project export");
        // The other protected method of the bean is still the scanned one.
        assertThat(registry.findByResourceId(Operations.class.getName() + "#readDocument")).isPresent();
    }

    /** PR-13: a call of a final method runs on the proxy itself: the application answered 500 and the start said nothing. */
    @Test
    void theStartNamesAProtectedMethodThatIsFinal() {
        List<String> warnings = warningsOf(new WithFinalMethods());

        assertThat(warnings).anySatisfy(warning -> assertThat(warning)
                .contains(WithFinalMethods.class.getName() + "#finalRead").contains("final"));
    }

    @Test
    void theStartNamesAFinalMethodOfAProtectedClassThatIsNotAnnotatedItself() {
        List<String> warnings = warningsOf(new WithFinalMethods());

        assertThat(warnings).anySatisfy(warning -> assertThat(warning).contains("#finalHelper"));
    }

    @Test
    void theStartNamesAFinalMethodOfAClassProtectedAsAWhole() {
        List<String> warnings = warningsOf(new ProtectedAsAWhole());

        assertThat(warnings).anySatisfy(warning -> assertThat(warning).contains("#finalEverything"));
    }

    @Test
    void theStartNamesAFinalMethodTheClassInherits() {
        List<String> warnings = warningsOf(new InheritsAFinalMethod());

        assertThat(warnings).anySatisfy(warning -> assertThat(warning)
                .contains(FinalBase.class.getName() + "#inheritedFinal"));
    }

    @Test
    void whatAProxyHasNoNeedToInterceptIsNotNamed() {
        List<String> warnings = warningsOf(new WithFinalMethods());

        assertThat(warnings).noneSatisfy(warning -> assertThat(warning).contains("#finalPrivate"));
        assertThat(warnings).noneSatisfy(warning -> assertThat(warning).contains("#finalStatic"));
        assertThat(warnings).noneSatisfy(warning -> assertThat(warning).contains("#ordinaryRead"));
        assertThat(warnings).noneSatisfy(warning -> assertThat(warning).contains("#getClass"));
    }

    @Test
    void aClassWithoutProtectionIsNotNamed() {
        assertThat(warningsOf(new NotProtected())).isEmpty();
    }

    private static List<String> warningsOf(Object bean) {
        Logger logger = (Logger) LoggerFactory.getLogger(ProtectableResourceContextScanner.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            scanned(bean);
            return appender.list.stream()
                    .filter(event -> event.getLevel() == Level.WARN)
                    .map(ILoggingEvent::getFormattedMessage)
                    .toList();
        } finally {
            logger.detachAppender(appender);
        }
    }

    public static class WithFinalMethods {

        @Protectable
        public final void finalRead() {
        }

        @Protectable
        public void ordinaryRead() {
            finalPrivate();
        }

        public final void finalHelper() {
        }

        private final void finalPrivate() {
        }

        public static final void finalStatic() {
        }
    }

    @Protectable
    public static class ProtectedAsAWhole {

        public void everything() {
        }

        public final void finalEverything() {
        }
    }

    public static class FinalBase {

        public final void inheritedFinal() {
        }
    }

    public static class InheritsAFinalMethod extends FinalBase {

        @Protectable
        public void read() {
        }
    }

    public static class NotProtected {

        public final void finalButNotProtected() {
        }
    }

    private static InMemoryResourceContextRegistry scanned(Object bean) {
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerSingleton("bean", bean);
        InMemoryResourceContextRegistry registry = new InMemoryResourceContextRegistry();
        new ProtectableResourceContextScanner(beanFactory, registry).afterSingletonsInstantiated();
        return registry;
    }

    public static class Operations {

        @Protectable(category = "PROJECT_DOCUMENTS", sensitivity = "RESTRICTED", actions = "EXPORT",
                exportSensitive = true)
        public void exportDocuments() {
        }

        @Protectable
        public void readDocument() {
        }

        public void health() {
        }
    }

    @Protectable(privileged = true)
    public static class AdminOperations {

        public void grantRole() {
        }

        public void revokeRole() {
        }
    }

    public static class ImportanceOperations {

        @Protectable(importance = ResourceImportance.NON_SENSITIVE)
        public void listTitles() {
        }

        @Protectable(importance = ResourceImportance.SENSITIVE, actions = "EXPORT")
        public void exportAll() {
        }

        @Protectable(importance = ResourceImportance.SENSITIVE)
        public void readRecord() {
        }
    }

    @Protectable(importance = ResourceImportance.SENSITIVE)
    public static class SensitiveClass {

        public void readRecord() {
        }

        @Protectable(importance = ResourceImportance.NON_SENSITIVE)
        public void listTitles() {
        }
    }

    public interface SensitiveLookup {

        @Protectable(category = "CUSTOMER_RECORDS", importance = ResourceImportance.SENSITIVE)
        void readCustomer();
    }

    public interface CustomerLookup {

        @Protectable(category = "CUSTOMER_RECORDS")
        void readCustomer();
    }
}
