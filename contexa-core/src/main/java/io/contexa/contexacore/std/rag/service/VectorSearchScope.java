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

import io.contexa.contexacore.std.rag.constants.VectorDocumentMetadata;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * The scope of a vector search or of a written document (W2-15): the one user and the one organisation it requires.
 * A search whose filter requires one user is a personal search; pgvector applies a filter after it walks an
 * approximate index, so such a search reads the user's records exactly. A written document reaches the searches whose
 * results it can change: its user's, its organisation's and those that require neither.
 *
 * @param userId         the user the search requires (an equality joined by AND), or the user of the document
 * @param organizationId the organisation the search requires, or the organisation of the document
 */
public record VectorSearchScope(String userId, String organizationId) {

    /** The scope a search filter requires: equality conditions on the user and the organisation joined by AND. */
    public static VectorSearchScope of(Filter.Expression filter) {
        Map<String, String> required = new HashMap<>();
        collect(filter, required);
        return new VectorSearchScope(required.get(VectorDocumentMetadata.USER_ID),
                required.get(VectorDocumentMetadata.ORGANIZATION_ID));
    }

    /** The scope of a written document, from its metadata. */
    public static VectorSearchScope ofDocument(Document document) {
        Map<String, Object> metadata = document != null ? document.getMetadata() : null;
        if (metadata == null) {
            return new VectorSearchScope(null, null);
        }
        return new VectorSearchScope(text(metadata.get(VectorDocumentMetadata.USER_ID)),
                text(metadata.get(VectorDocumentMetadata.ORGANIZATION_ID)));
    }

    /** Whether the search requires one user. */
    public boolean personal() {
        return userId != null;
    }

    /** Whether the scope names neither a user nor an organisation. */
    public boolean unscoped() {
        return userId == null && organizationId == null;
    }

    /** Whether a written document of this scope can change the results of the given search. */
    public boolean reaches(VectorSearchScope search) {
        if (search == null || search.unscoped() || unscoped()) {
            return true;
        }
        if (search.userId() != null) {
            return search.userId().equals(userId);
        }
        return search.organizationId().equals(organizationId);
    }

    private static void collect(Filter.Operand operand, Map<String, String> required) {
        if (operand instanceof Filter.Group group) {
            collect(group.content(), required);
            return;
        }
        if (!(operand instanceof Filter.Expression expression) || expression.type() == null) {
            return;
        }
        if (expression.type() == Filter.ExpressionType.AND) {
            collect(expression.left(), required);
            collect(expression.right(), required);
            return;
        }
        if (expression.type() == Filter.ExpressionType.EQ
                && expression.left() instanceof Filter.Key key
                && expression.right() instanceof Filter.Value value) {
            String name = key.key();
            String text = text(value.value());
            if (text != null && (VectorDocumentMetadata.USER_ID.equals(name)
                    || VectorDocumentMetadata.ORGANIZATION_ID.equals(name))) {
                required.putIfAbsent(name, text);
            }
        }
    }

    private static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString();
        return StringUtils.hasText(text) ? text : null;
    }
}
