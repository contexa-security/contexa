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
package io.contexa.contexacore.std.llm.exception;

public class ModelSelectionException extends RuntimeException {

    private final String modelName;
    private final Integer tier;

    public ModelSelectionException(String message) {
        super(message);
        this.modelName = null;
        this.tier = null;
    }

    public ModelSelectionException(String message, Throwable cause) {
        super(message, cause);
        this.modelName = null;
        this.tier = null;
    }

    public ModelSelectionException(String message, String modelName) {
        super(message);
        this.modelName = modelName;
        this.tier = null;
    }

    public ModelSelectionException(String message, Integer tier) {
        super(message);
        this.modelName = null;
        this.tier = tier;
    }

    public ModelSelectionException(String message, String modelName, Throwable cause) {
        super(message, cause);
        this.modelName = modelName;
        this.tier = null;
    }

    public String getModelName() {
        return modelName;
    }

    public Integer getTier() {
        return tier;
    }
}