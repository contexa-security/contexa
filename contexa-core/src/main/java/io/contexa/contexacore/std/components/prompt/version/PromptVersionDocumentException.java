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
package io.contexa.contexacore.std.components.prompt.version;

import java.util.List;
import java.util.stream.Collectors;

/** A prompt version document that cannot be read or saved, with every problem found in it. */
public class PromptVersionDocumentException extends RuntimeException {

    private final transient List<PromptVersionProblem> problems;

    public PromptVersionDocumentException(List<PromptVersionProblem> problems) {
        super(problems.stream()
                .map(problem -> problem.code() + (problem.where() != null ? " at " + problem.where() : "")
                        + (problem.detail() != null ? ": " + problem.detail() : ""))
                .collect(Collectors.joining("; ")));
        this.problems = List.copyOf(problems);
    }

    public List<PromptVersionProblem> problems() {
        return problems;
    }
}
