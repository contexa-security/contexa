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
package io.contexa.contexacore.testsupport;

import io.contexa.contexacommon.store.ApplicationNamespace;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Runs each test as an application that has a name ({@code spring.application.name}), so that a contract test written for
 * a store answers for the store of a named application with the same assertions it has for an unnamed one: a subclass of
 * the test with {@code @ExtendWith(NamedApplication.class)} is that second run.
 */
public final class NamedApplication implements BeforeEachCallback, AfterEachCallback {

    /** The name the second run of a contract test gives the application. */
    public static final String NAME = "contract-app";

    private static final ExtensionContext.Namespace STORE = ExtensionContext.Namespace.create(NamedApplication.class);
    private static final String SCOPE = "scope";

    @Override
    public void beforeEach(ExtensionContext context) {
        context.getStore(STORE).put(SCOPE, ApplicationNamespace.using(NAME));
    }

    @Override
    public void afterEach(ExtensionContext context) {
        ApplicationNamespace.Scope scope = context.getStore(STORE).remove(SCOPE, ApplicationNamespace.Scope.class);
        if (scope != null) {
            scope.close();
        }
    }
}
