package io.contexa.contexacommon.domain.context;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DomainContextTest {

    // Concrete implementation for testing the abstract class
    private static class TestDomainContext extends DomainContext {

        private static final String TEST_DOMAIN = "TEST_DOMAIN";

        TestDomainContext() {
            super();
        }

        TestDomainContext(String userId, String sessionId) {
            super(userId, sessionId);
        }

        @Override
        public String getDomainType() {
            return TEST_DOMAIN;
        }
    }

    private TestDomainContext context;

    @BeforeEach
    void setUp() {
        context = new TestDomainContext();
    }

    @Test
    @DisplayName("Default constructor generates unique contextId")
    void defaultConstructor_shouldGenerateUniqueContextId() {
        TestDomainContext ctx1 = new TestDomainContext();
        TestDomainContext ctx2 = new TestDomainContext();

        assertThat(ctx1.getContextId()).isNotNull();
        assertThat(ctx2.getContextId()).isNotNull();
        assertThat(ctx1.getContextId()).isNotEqualTo(ctx2.getContextId());
    }

    @Test
    @DisplayName("Default constructor sets createdAt to current time")
    void defaultConstructor_shouldSetCreatedAtToCurrentTime() {
        LocalDateTime before = LocalDateTime.now();
        TestDomainContext ctx = new TestDomainContext();
        LocalDateTime after = LocalDateTime.now();

        assertThat(ctx.getCreatedAt()).isAfterOrEqualTo(before);
        assertThat(ctx.getCreatedAt()).isBeforeOrEqualTo(after);
    }

    @Test
    @DisplayName("Parameterized constructor sets userId and sessionId")
    void parameterizedConstructor_shouldSetUserIdAndSessionId() {
        TestDomainContext ctx = new TestDomainContext("user-1", "session-1");

        assertThat(ctx.getUserId()).isEqualTo("user-1");
        assertThat(ctx.getSessionId()).isEqualTo("session-1");
        assertThat(ctx.getContextId()).isNotNull();
        assertThat(ctx.getCreatedAt()).isNotNull();
    }

    @Test
    @DisplayName("addMetadata stores key-value pair")
    void addMetadata_shouldStoreKeyValuePair() {
        context.addMetadata("key1", "value1");
        context.addMetadata("key2", 42);

        assertThat(context.getMetadata("key1", String.class)).isEqualTo("value1");
        assertThat(context.getMetadata("key2", Integer.class)).isEqualTo(42);
    }

    @Test
    @DisplayName("addMetadata overwrites existing key")
    void addMetadata_shouldOverwriteExistingKey() {
        context.addMetadata("key", "original");
        context.addMetadata("key", "updated");

        assertThat(context.getMetadata("key", String.class)).isEqualTo("updated");
    }

    @Test
    @DisplayName("getMetadata returns null for non-existent key")
    void getMetadata_shouldReturnNullForNonExistentKey() {
        assertThat(context.getMetadata("nonexistent", String.class)).isNull();
    }

    @Test
    @DisplayName("getMetadata returns null when type does not match")
    void getMetadata_shouldReturnNullWhenTypeMismatch() {
        context.addMetadata("key", "string-value");

        // Requesting as Integer when value is String
        assertThat(context.getMetadata("key", Integer.class)).isNull();
    }

    @Test
    @DisplayName("getMetadata returns value when type matches")
    void getMetadata_shouldReturnValueWhenTypeMatches() {
        context.addMetadata("count", 100L);

        assertThat(context.getMetadata("count", Long.class)).isEqualTo(100L);
    }

    @Test
    @DisplayName("getAllMetadata returns immutable copy")
    void getAllMetadata_shouldReturnImmutableCopy() {
        context.addMetadata("key1", "value1");

        Map<String, Object> allMetadata = context.getAllMetadata();

        assertThat(allMetadata).containsEntry("key1", "value1");

        // Verify immutability - modifying the returned map should throw
        try {
            allMetadata.put("key2", "value2");
            // If no exception, fail the test
            assertThat(true).as("Expected UnsupportedOperationException").isFalse();
        } catch (UnsupportedOperationException e) {
            // Expected behavior
        }
    }

    @Test
    @DisplayName("getAllMetadata does not reflect subsequent changes to original")
    void getAllMetadata_shouldNotReflectSubsequentChanges() {
        context.addMetadata("key1", "value1");

        Map<String, Object> snapshot = context.getAllMetadata();

        context.addMetadata("key2", "value2");

        assertThat(snapshot).doesNotContainKey("key2");
    }

    @Test
    @DisplayName("getDomainType returns the concrete implementation domain type")
    void getDomainType_shouldReturnConcreteType() {
        assertThat(context.getDomainType()).isEqualTo("TEST_DOMAIN");
    }

    @Test
    @DisplayName("toString contains class name, contextId, and domain type")
    void toString_shouldContainExpectedFields() {
        String str = context.toString();

        assertThat(str).contains("TestDomainContext");
        assertThat(str).contains(context.getContextId());
        assertThat(str).contains("TEST_DOMAIN");
    }
}
