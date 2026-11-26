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
package io.contexa.contexacore.std.llm.client;

import org.springframework.ai.chat.model.ChatModel;

import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * R-9: the chat model instances Contexa made for its own calls: the copies and model variants of the application's chat
 * models ({@code ChatModelVariants}). Spring AI merges a model's default options into every request it sends, and a
 * request cannot take a default out, so what Contexa's calls must not carry (a sampling value the model refuses, the
 * max_tokens field of an OpenAI reasoning model, a field the provider refused) is left out of the defaults. Contexa does
 * that only in the defaults of these instances. Any other chat model is the application's, and Contexa sets nothing in
 * it. The instances are held weakly, and an instance counts only as itself, not as another that equals it.
 */
public final class ContexaChatModelInstances {

    private static final Map<ChatModel, WeakReference<ChatModel>> INSTANCES =
            Collections.synchronizedMap(new WeakHashMap<>());

    private ContexaChatModelInstances() {
    }

    /** Records a chat model Contexa made for its own calls, and returns it. */
    public static <T extends ChatModel> T add(T model) {
        if (model != null) {
            INSTANCES.put(model, new WeakReference<>(model));
        }
        return model;
    }

    /** Whether the chat model is one Contexa made for its own calls. */
    public static boolean isContexas(ChatModel model) {
        if (model == null) {
            return false;
        }
        WeakReference<ChatModel> held = INSTANCES.get(model);
        return held != null && held.get() == model;
    }
}
