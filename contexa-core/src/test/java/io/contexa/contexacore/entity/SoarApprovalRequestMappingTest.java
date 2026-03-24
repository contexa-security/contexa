package io.contexa.contexacore.entity;

import io.contexa.contexacore.domain.entity.SoarApprovalRequest;
import jakarta.persistence.Column;
import jakarta.persistence.Lob;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;

class SoarApprovalRequestMappingTest {

    @Test
    void longTextColumnsShouldUseTextInsteadOfLob() throws Exception {
        assertTextColumnWithoutLob("description");
        assertTextColumnWithoutLob("reviewerComment");
        assertTextColumnWithoutLob("approvalComment");
        assertTextColumnWithoutLob("breakGlassReason");
        assertTextColumnWithoutLob("parameters");
        assertTextColumnWithoutLob("requiredRoles");
    }

    @Test
    void reviewerCommentShouldMapToSnakeCaseColumn() throws Exception {
        Field field = SoarApprovalRequest.class.getDeclaredField("reviewerComment");
        Column column = field.getAnnotation(Column.class);

        assertThat(column).isNotNull();
        assertThat(column.name()).isEqualTo("reviewer_comment");
    }

    @Test
    void approvalCommentShouldMapToApprovalCommentColumn() throws Exception {
        Field field = SoarApprovalRequest.class.getDeclaredField("approvalComment");
        Column column = field.getAnnotation(Column.class);

        assertThat(column).isNotNull();
        assertThat(column.name()).isEqualTo("approval_comment");
        assertThat(column.columnDefinition()).isEqualTo("TEXT");
    }

    private void assertTextColumnWithoutLob(String fieldName) throws Exception {
        Field field = SoarApprovalRequest.class.getDeclaredField(fieldName);
        Column column = field.getAnnotation(Column.class);
        Lob lob = field.getAnnotation(Lob.class);

        assertThat(lob)
                .withFailMessage("%s must not use @Lob because PostgreSQL migrates String LOB to oid", fieldName)
                .isNull();
        assertThat(column)
                .withFailMessage("%s must declare @Column(columnDefinition = \"TEXT\")", fieldName)
                .isNotNull();
        assertThat(column.columnDefinition()).isEqualTo("TEXT");
    }
}
