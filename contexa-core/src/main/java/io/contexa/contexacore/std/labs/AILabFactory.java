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
package io.contexa.contexacore.std.labs;

import java.util.Optional;

public interface AILabFactory {

    <T extends AILab<?, ?>> Optional<T> getLab(Class<T> labType);

    <T extends AILab<?, ?>> T createLab(Class<T> labType);

    Optional<AILab<?, ?>> getLabByClassName(String className);

    default boolean hasLab(Class<? extends AILab<?, ?>> labType) {
        return getLab(labType).isPresent();
    }

    default boolean hasLab(String className) {
        return getLabByClassName(className).isPresent();
    }
}
