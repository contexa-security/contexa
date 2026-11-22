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
package io.contexa.contexacore.std.components.prompt.quality;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * A set of labelled cases (plan 3.2). Its version is fixed by the content of its cases, so a measurement names the
 * exact cases it was taken with.
 *
 * @param name  the name of the set
 * @param cases the cases, each key once
 */
public record QualityCaseSet(String name, List<QualityCase> cases) {

    /** The name of the default set Contexa ships. */
    public static final String CONTEXA_DEFAULT = "contexa-default";

    public QualityCaseSet {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("A case set needs a name");
        }
        name = name.trim();
        cases = List.copyOf(cases);
        Set<String> keys = new HashSet<>();
        for (QualityCase item : cases) {
            if (!keys.add(item.key())) {
                throw new IllegalArgumentException("The case " + item.key() + " is listed twice in the set " + name);
            }
        }
    }

    /**
     * The version of the set: the hash of the keys and content hashes of its cases. The order of the cases and the
     * name of the set do not count.
     */
    public String version() {
        return QualityCaseHashes.setVersion(cases);
    }

    public Optional<QualityCase> find(String key) {
        return cases.stream().filter(item -> item.key().equals(key)).findFirst();
    }
}
