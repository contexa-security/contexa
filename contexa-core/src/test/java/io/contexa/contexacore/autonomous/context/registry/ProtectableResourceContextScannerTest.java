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

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.autonomous.context.model.ResourceContextDescriptor;
import org.junit.jupiter.api.Test;
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

    public interface CustomerLookup {

        @Protectable(category = "CUSTOMER_RECORDS")
        void readCustomer();
    }
}
