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

import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelectionSource;

import java.lang.ref.WeakReference;
import java.util.function.Supplier;

/**
 * One version for one request (plan 3.4): the prompt generator asks a template for the system prompt, then the user
 * prompt, then the descriptor of the call, on one thread. The version chosen for the request's system prompt is kept
 * for the rest of that request, so a label moved in between does not mix two versions in one call.
 */
public final class PromptVersionPin {

    private final ThreadLocal<Pinned> pinned = new ThreadLocal<>();
    private final ThreadLocal<PromptVersionInUse.Choice> drawing = new ThreadLocal<>();

    private record Pinned(WeakReference<Object> request, PromptVersionInUse.Choice choice) {
    }

    /**
     * What the drawing gives while every request on this thread draws the version: the version screen's example of
     * a version that does not decide (plan 3.11).
     */
    public <T> T with(AssembledPrompt version, Supplier<T> draw) {
        PromptVersionInUse.Choice before = drawing.get();
        drawing.set(new PromptVersionInUse.Choice(version, version.release() != null ? version.release() : "example",
                PromptBundleSelectionSource.BUILD_DEFAULT));
        try {
            return draw.get();
        }
        finally {
            if (before != null) {
                drawing.set(before);
            }
            else {
                drawing.remove();
            }
        }
    }

    /** The version of the request: the one already chosen for it on this thread, else a new choice kept for it. */
    public PromptVersionInUse.Choice of(Object request, Supplier<PromptVersionInUse.Choice> choose) {
        PromptVersionInUse.Choice forced = drawing.get();
        if (forced != null) {
            return forced;
        }
        Pinned current = pinned.get();
        if (request != null && current != null && current.request().get() == request) {
            return current.choice();
        }
        PromptVersionInUse.Choice choice = choose.get();
        pinned.set(new Pinned(new WeakReference<>(request), choice));
        return choice;
    }

    /** The version of the last request on this thread, for the descriptor of its call; else a new choice. */
    public PromptVersionInUse.Choice last(Supplier<PromptVersionInUse.Choice> choose) {
        Pinned current = pinned.get();
        return current != null ? current.choice() : choose.get();
    }
}
