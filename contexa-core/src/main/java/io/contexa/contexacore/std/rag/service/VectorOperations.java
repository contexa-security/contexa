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
package io.contexa.contexacore.std.rag.service;

import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;

import java.util.List;
import java.util.Map;

public interface VectorOperations {

    void storeDocument(Document document);

    void storeDocuments(List<Document> documents);

    List<Document> searchSimilar(String query);

    List<Document> searchSimilar(String query, Map<String, Object> filters);

    List<Document> searchSimilar(SearchRequest searchRequest);

    void deleteDocuments(List<String> documentIds);

    class VectorStoreException extends RuntimeException {
        public VectorStoreException(String message) {
            super(message);
        }

        public VectorStoreException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
