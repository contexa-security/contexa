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
package io.contexa.contexacommon.hcad.domain;


public enum BaselineMatchStatus {

    
    MATCH("MATCH", "All criteria matched"),

    
    PARTIAL("PARTIAL", "Same browser and OS, version differs (normal auto-update)"),

    
    MISMATCH("MISMATCH", "Criteria mismatch, possible account takeover"),

    
    UNKNOWN("UNKNOWN", "Cannot compare, data unavailable");

    private final String code;
    private final String description;

    BaselineMatchStatus(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }

    
    public static BaselineMatchStatus fromString(String status) {
        if (status == null) {
            return UNKNOWN;
        }
        for (BaselineMatchStatus s : values()) {
            if (s.code.equalsIgnoreCase(status)) {
                return s;
            }
        }
        return UNKNOWN;
    }

    
    @Override
    public String toString() {
        return code;
    }
}
