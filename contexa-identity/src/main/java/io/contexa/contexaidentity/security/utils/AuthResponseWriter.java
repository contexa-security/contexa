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
package io.contexa.contexaidentity.security.utils;

import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;

public interface AuthResponseWriter {
    
    void writeSuccessResponse(HttpServletResponse response, Object data, int status) throws IOException;

    void writeErrorResponse(HttpServletResponse response, int status, String errorCode, String errorMessage, String path) throws IOException;

    void writeErrorResponse(HttpServletResponse response, int scUnauthorized, String errorCode, String errorMessage, String requestURI, Map<String, Object> errorDetails) throws IOException;

}
