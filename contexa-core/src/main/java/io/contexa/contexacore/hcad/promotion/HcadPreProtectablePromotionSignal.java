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
package io.contexa.contexacore.hcad.promotion;

public enum HcadPreProtectablePromotionSignal {
    IMPOSSIBLE_TRAVEL(true, 45),
    NEW_DEVICE(true, 25),
    FAILED_LOGIN_BURST(true, 30),
    AUTH_CONTEXT_INCONSISTENT(true, 40),
    REQUEST_BURST(false, 10),
    RAPID_SEQUENCE(false, 10),
    PREVIOUS_PATH_JUMP(false, 10),
    SENSITIVE_SURFACE(false, 20),
    BASELINE_UNCERTAIN(false, 5);

    private final boolean anchor;
    private final int weight;

    HcadPreProtectablePromotionSignal(boolean anchor, int weight) {
        this.anchor = anchor;
        this.weight = weight;
    }

    public boolean isAnchor() {
        return anchor;
    }

    public int weight() {
        return weight;
    }
}