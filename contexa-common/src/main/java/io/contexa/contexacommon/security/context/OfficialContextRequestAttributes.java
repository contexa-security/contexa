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
package io.contexa.contexacommon.security.context;

import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;
import java.util.Map;

public final class OfficialContextRequestAttributes {

    private OfficialContextRequestAttributes() {
    }

    public static Map<String, Object> extractSnapshot(HttpServletRequest request) {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        if (request == null) {
            return snapshot;
        }
        for (OfficialContextField field : OfficialContextField.values()) {
            Object value = field.extract(request);
            if (value != null) {
                snapshot.put(field.metadataKey(), value);
            }
        }
        return snapshot;
    }

    public static void applySnapshot(HttpServletRequest request, Map<String, ?> snapshot, boolean overwriteExisting) {
        if (request == null || snapshot == null || snapshot.isEmpty()) {
            return;
        }
        for (Map.Entry<String, ?> entry : snapshot.entrySet()) {
            OfficialContextField field = OfficialContextField.fromMetadataKey(entry.getKey());
            if (field != null) {
                field.project(request, entry.getValue(), overwriteExisting);
            }
        }
    }

}
