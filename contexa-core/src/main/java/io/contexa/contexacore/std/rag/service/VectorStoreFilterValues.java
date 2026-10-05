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

import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;

import java.util.ArrayList;
import java.util.List;

/**
 * Encodes the string values of a metadata filter for the vector store that will render it.
 * <p>
 * Spring AI's pgvector store writes filter values into its SQL as {@code '... "value" ...'::jsonpath} without
 * escaping them, so a value such as a user name with an apostrophe breaks the statement or changes its meaning.
 * For that store every string value is escaped first for the jsonpath string literal and then for the SQL string
 * literal (standard conforming strings). Other stores render values through their own converters and are left as is.
 * Every filter Contexa sends to a vector store goes through this class.
 */
public final class VectorStoreFilterValues {

    private static final String PG_VECTOR_STORE = "org.springframework.ai.vectorstore.pgvector.PgVectorStore";

    private VectorStoreFilterValues() {
    }

    public static SearchRequest encode(SearchRequest request, VectorStore vectorStore) {
        if (request == null || !request.hasFilterExpression() || !rendersValuesIntoSql(vectorStore)) {
            return request;
        }
        return SearchRequest.from(request).filterExpression(encodeExpression(request.getFilterExpression())).build();
    }

    public static Filter.Expression encode(Filter.Expression expression, VectorStore vectorStore) {
        if (expression == null || !rendersValuesIntoSql(vectorStore)) {
            return expression;
        }
        return encodeExpression(expression);
    }

    static boolean rendersValuesIntoSql(VectorStore vectorStore) {
        for (Class<?> type = vectorStore == null ? null : vectorStore.getClass(); type != null; type = type.getSuperclass()) {
            if (PG_VECTOR_STORE.equals(type.getName())) {
                return true;
            }
        }
        return false;
    }

    static Filter.Expression encodeExpression(Filter.Expression expression) {
        return new Filter.Expression(expression.type(), encodeOperand(expression.left()), encodeOperand(expression.right()));
    }

    private static Filter.Operand encodeOperand(Filter.Operand operand) {
        if (operand instanceof Filter.Expression expression) {
            return encodeExpression(expression);
        }
        if (operand instanceof Filter.Group group) {
            return new Filter.Group(encodeExpression(group.content()));
        }
        if (operand instanceof Filter.Value value) {
            return new Filter.Value(encodeValue(value.value()));
        }
        return operand;
    }

    private static Object encodeValue(Object value) {
        if (value instanceof String text) {
            return encodeString(text);
        }
        if (value instanceof List<?> values) {
            List<Object> encoded = new ArrayList<>(values.size());
            for (Object element : values) {
                encoded.add(encodeValue(element));
            }
            return encoded;
        }
        return value;
    }

    static String encodeString(String value) {
        String jsonPathLiteral = value.replace("\\", "\\\\").replace("\"", "\\\"");
        return jsonPathLiteral.replace("'", "''");
    }
}
