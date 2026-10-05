package io.contexa.contexacore.std.rag.service;

import org.junit.jupiter.api.Test;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class VectorStoreFilterValuesTest {

    @Test
    void stringValuesAreEscapedForTheJsonPathLiteralAndThenForTheSqlLiteral() {
        assertThat(VectorStoreFilterValues.encodeString("o'brien")).isEqualTo("o''brien");
        assertThat(VectorStoreFilterValues.encodeString("say \"hi\"")).isEqualTo("say \\\"hi\\\"");
        assertThat(VectorStoreFilterValues.encodeString("a\\b")).isEqualTo("a\\\\b");
        assertThat(VectorStoreFilterValues.encodeString("plain-user")).isEqualTo("plain-user");
    }

    @Test
    void everyStringValueInTheExpressionTreeIsEncodedAndOtherValuesAreKept() {
        FilterExpressionBuilder b = new FilterExpressionBuilder();
        Filter.Expression expression = b.and(
                b.eq("userId", "o'brien"),
                b.group(b.or(b.in("documentType", "behavior", "it's"), b.gte("hour", 9)))).build();

        Filter.Expression encoded = VectorStoreFilterValues.encodeExpression(expression);

        Filter.Expression expected = b.and(
                b.eq("userId", "o''brien"),
                b.group(b.or(b.in("documentType", "behavior", "it''s"), b.gte("hour", 9)))).build();
        assertThat(encoded).isEqualTo(expected);
    }

    @Test
    void storesThatRenderValuesThemselvesReceiveTheFilterUnchanged() {
        VectorStore otherStore = mock(VectorStore.class);
        Filter.Expression expression = new FilterExpressionBuilder().eq("userId", "o'brien").build();
        SearchRequest request = SearchRequest.builder().query("q").filterExpression(expression).build();

        assertThat(VectorStoreFilterValues.rendersValuesIntoSql(otherStore)).isFalse();
        assertThat(VectorStoreFilterValues.encode(expression, otherStore)).isSameAs(expression);
        assertThat(VectorStoreFilterValues.encode(request, otherStore)).isSameAs(request);
        assertThat(VectorStoreFilterValues.encode((SearchRequest) null, otherStore)).isNull();
    }
}
