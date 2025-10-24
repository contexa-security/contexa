package io.contexa.contexamcp.utils;

import com.fasterxml.jackson.annotation.JsonClassDescription;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;

/**
 * JSON Schema Generator Utility
 * 
 * Request/Response 클래스로부터 JSON Schema를 동적으로 생성하는 유틸리티
 * Spring AI의 Tool 정의에 필요한 inputSchema를 자동 생성
 * 
 * 주요 기능:
 * - Jackson 어노테이션 기반 스키마 생성
 * - 중첩된 객체 구조 지원
 * - 컬렉션 타입 지원
 * - required 필드 자동 감지
 * - 설명(description) 자동 추출
 */
@Slf4j
@UtilityClass
public class JsonSchemaGenerator {
    
    private static final ObjectMapper MAPPER = new ObjectMapper();
    
    /**
     * 클래스로부터 JSON Schema 생성
     * 
     * @param clazz 스키마를 생성할 클래스
     * @return JSON Schema 문자열
     */
    public static String generateSchema(Class<?> clazz) {
        try {
            ObjectNode schema = generateSchemaNode(clazz);
            return MAPPER.writerWithDefaultPrettyPrinter()
                         .writeValueAsString(schema);
        } catch (Exception e) {
            log.error("Failed to generate JSON schema for class: {}", clazz.getName(), e);
            // 폴백: 기본 스키마 반환
            return generateDefaultSchema();
        }
    }
    
    /**
     * 클래스로부터 JSON Schema 노드 생성
     * 
     * @param clazz 스키마를 생성할 클래스
     * @return JSON Schema ObjectNode
     */
    public static ObjectNode generateSchemaNode(Class<?> clazz) {
        ObjectNode schema = MAPPER.createObjectNode();
        
        // 기본 스키마 정보
        schema.put("$schema", "http://json-schema.org/draft-07/schema#");
        schema.put("type", "object");
        
        // 클래스 설명 추가
        JsonClassDescription classDesc = clazz.getAnnotation(JsonClassDescription.class);
        if (classDesc != null) {
            schema.put("description", classDesc.value());
        }
        
        // Properties 생성
        ObjectNode properties = MAPPER.createObjectNode();
        ArrayNode required = MAPPER.createArrayNode();
        
        // Record 클래스 처리
        if (clazz.isRecord()) {
            processRecordClass(clazz, properties, required);
        } else {
            // 일반 클래스 처리
            processRegularClass(clazz, properties, required);
        }
        
        schema.set("properties", properties);
        
        if (required.size() > 0) {
            schema.set("required", required);
        }
        
        // additionalProperties 설정
        schema.put("additionalProperties", false);
        
        return schema;
    }
    
    /**
     * Record 클래스 처리
     */
    private static void processRecordClass(Class<?> clazz, ObjectNode properties, ArrayNode required) {
        try {
            var recordComponents = clazz.getRecordComponents();
            if (recordComponents != null) {
                for (var component : recordComponents) {
                    String fieldName = component.getName();
                    Class<?> fieldType = component.getType();
                    Type genericType = component.getGenericType();
                    
                    // JsonProperty 어노테이션 확인
                    JsonProperty jsonProperty = component.getAnnotation(JsonProperty.class);
                    if (jsonProperty != null) {
                        // 필드 이름 오버라이드
                        if (!jsonProperty.value().isEmpty()) {
                            fieldName = jsonProperty.value();
                        }
                        
                        // required 확인
                        if (jsonProperty.required()) {
                            required.add(fieldName);
                        }
                    }
                    
                    // 필드 스키마 생성
                    ObjectNode fieldSchema = createFieldSchema(fieldType, genericType);
                    
                    // 설명 추가
                    JsonPropertyDescription propDesc = component.getAnnotation(JsonPropertyDescription.class);
                    if (propDesc != null) {
                        fieldSchema.put("description", propDesc.value());
                    }
                    
                    properties.set(fieldName, fieldSchema);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to process record class: {}", clazz.getName(), e);
        }
    }
    
    /**
     * 일반 클래스 처리
     */
    private static void processRegularClass(Class<?> clazz, ObjectNode properties, ArrayNode required) {
        // 모든 필드 수집 (상속된 필드 포함)
        List<Field> allFields = getAllFields(clazz);
        
        for (Field field : allFields) {
            // static, transient 필드 제외
            if (java.lang.reflect.Modifier.isStatic(field.getModifiers()) ||
                java.lang.reflect.Modifier.isTransient(field.getModifiers())) {
                continue;
            }
            
            String fieldName = field.getName();
            Class<?> fieldType = field.getType();
            Type genericType = field.getGenericType();
            
            // JsonProperty 어노테이션 확인
            JsonProperty jsonProperty = field.getAnnotation(JsonProperty.class);
            if (jsonProperty != null) {
                // 필드 이름 오버라이드
                if (!jsonProperty.value().isEmpty()) {
                    fieldName = jsonProperty.value();
                }
                
                // required 확인
                if (jsonProperty.required()) {
                    required.add(fieldName);
                }
            }
            
            // 필드 스키마 생성
            ObjectNode fieldSchema = createFieldSchema(fieldType, genericType);
            
            // 설명 추가
            JsonPropertyDescription propDesc = field.getAnnotation(JsonPropertyDescription.class);
            if (propDesc != null) {
                fieldSchema.put("description", propDesc.value());
            }
            
            properties.set(fieldName, fieldSchema);
        }
    }
    
    /**
     * 필드 타입에 따른 스키마 생성
     */
    private static ObjectNode createFieldSchema(Class<?> fieldType, Type genericType) {
        ObjectNode schema = MAPPER.createObjectNode();
        
        // Primitive 및 Wrapper 타입
        if (fieldType == String.class) {
            schema.put("type", "string");
        } else if (fieldType == Integer.class || fieldType == int.class) {
            schema.put("type", "integer");
        } else if (fieldType == Long.class || fieldType == long.class) {
            schema.put("type", "integer");
            schema.put("format", "int64");
        } else if (fieldType == Double.class || fieldType == double.class) {
            schema.put("type", "number");
            schema.put("format", "double");
        } else if (fieldType == Float.class || fieldType == float.class) {
            schema.put("type", "number");
            schema.put("format", "float");
        } else if (fieldType == Boolean.class || fieldType == boolean.class) {
            schema.put("type", "boolean");
        } else if (fieldType == LocalDateTime.class) {
            schema.put("type", "string");
            schema.put("format", "date-time");
        } else if (fieldType == LocalDate.class) {
            schema.put("type", "string");
            schema.put("format", "date");
        } else if (fieldType == Date.class) {
            schema.put("type", "string");
            schema.put("format", "date-time");
        } else if (fieldType.isEnum()) {
            // Enum 타입
            schema.put("type", "string");
            ArrayNode enumValues = MAPPER.createArrayNode();
            for (Object constant : fieldType.getEnumConstants()) {
                enumValues.add(constant.toString());
            }
            schema.set("enum", enumValues);
        } else if (List.class.isAssignableFrom(fieldType) || Set.class.isAssignableFrom(fieldType)) {
            // 컬렉션 타입
            schema.put("type", "array");
            
            // Generic 타입 추출
            if (genericType instanceof ParameterizedType) {
                ParameterizedType paramType = (ParameterizedType) genericType;
                Type[] typeArgs = paramType.getActualTypeArguments();
                if (typeArgs.length > 0 && typeArgs[0] instanceof Class) {
                    Class<?> elementType = (Class<?>) typeArgs[0];
                    schema.set("items", createFieldSchema(elementType, elementType));
                } else {
                    // 기본 아이템 타입
                    ObjectNode items = MAPPER.createObjectNode();
                    items.put("type", "object");
                    schema.set("items", items);
                }
            } else {
                // 기본 아이템 타입
                ObjectNode items = MAPPER.createObjectNode();
                items.put("type", "object");
                schema.set("items", items);
            }
        } else if (Map.class.isAssignableFrom(fieldType)) {
            // Map 타입
            schema.put("type", "object");
            
            // Map의 value 타입 추출 시도
            if (genericType instanceof ParameterizedType) {
                ParameterizedType paramType = (ParameterizedType) genericType;
                Type[] typeArgs = paramType.getActualTypeArguments();
                if (typeArgs.length > 1 && typeArgs[1] instanceof Class) {
                    Class<?> valueType = (Class<?>) typeArgs[1];
                    schema.set("additionalProperties", createFieldSchema(valueType, valueType));
                } else {
                    schema.put("additionalProperties", true);
                }
            } else {
                schema.put("additionalProperties", true);
            }
        } else if (fieldType.isArray()) {
            // 배열 타입
            schema.put("type", "array");
            Class<?> componentType = fieldType.getComponentType();
            schema.set("items", createFieldSchema(componentType, componentType));
        } else {
            // 복잡한 객체 타입
            if (isSimpleValueClass(fieldType)) {
                // 간단한 값 객체는 문자열로 처리
                schema.put("type", "string");
            } else {
                // 중첩된 객체 구조
                schema.put("type", "object");
                
                // 순환 참조 방지를 위해 깊이 제한
                if (!fieldType.getPackage().getName().startsWith("java.")) {
                    try {
                        ObjectNode nestedSchema = generateSchemaNode(fieldType);
                        // $schema 제거 (중첩된 스키마에서는 불필요)
                        nestedSchema.remove("$schema");
                        return nestedSchema;
                    } catch (Exception e) {
                        log.debug("Could not generate nested schema for: {}", fieldType.getName());
                    }
                }
            }
        }
        
        return schema;
    }
    
    /**
     * 클래스의 모든 필드 가져오기 (상속 포함)
     */
    private static List<Field> getAllFields(Class<?> clazz) {
        List<Field> fields = new ArrayList<>();
        
        while (clazz != null && clazz != Object.class) {
            fields.addAll(Arrays.asList(clazz.getDeclaredFields()));
            clazz = clazz.getSuperclass();
        }
        
        return fields;
    }
    
    /**
     * 간단한 값 클래스인지 확인
     */
    private static boolean isSimpleValueClass(Class<?> clazz) {
        return clazz.isPrimitive() ||
               clazz == String.class ||
               Number.class.isAssignableFrom(clazz) ||
               clazz == Boolean.class ||
               clazz == Character.class ||
               clazz == Date.class ||
               clazz.getName().startsWith("java.time.");
    }
    
    /**
     * 기본 폴백 스키마 생성
     */
    private static String generateDefaultSchema() {
        return """
            {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "description": "Tool input parameters",
                "additionalProperties": true
            }
            """;
    }
    
    /**
     * 스키마 검증
     * 생성된 스키마가 유효한지 확인
     * 
     * @param schemaJson JSON Schema 문자열
     * @return 유효한 경우 true
     */
    public static boolean validateSchema(String schemaJson) {
        try {
            JsonNode schema = MAPPER.readTree(schemaJson);
            
            // 기본 검증: 필수 필드 확인
            if (!schema.has("type")) {
                log.warn("Schema missing 'type' field");
                return false;
            }
            
            String type = schema.get("type").asText();
            if (!"object".equals(type) && !"array".equals(type) && 
                !"string".equals(type) && !"number".equals(type) && 
                !"boolean".equals(type) && !"null".equals(type)) {
                log.warn("Invalid schema type: {}", type);
                return false;
            }
            
            // object 타입인 경우 properties 확인
            if ("object".equals(type) && !schema.has("properties")) {
                log.warn("Object schema missing 'properties' field");
                return false;
            }
            
            return true;
        } catch (Exception e) {
            log.error("Invalid JSON schema", e);
            return false;
        }
    }
    
    /**
     * 예제 스키마 생성 (테스트용)
     * 
     * @return 예제 JSON Schema
     */
    public static String generateExampleSchema() {
        ObjectNode schema = MAPPER.createObjectNode();
        schema.put("$schema", "http://json-schema.org/draft-07/schema#");
        schema.put("type", "object");
        schema.put("description", "Example tool input schema");
        
        ObjectNode properties = MAPPER.createObjectNode();
        
        // String 필드
        ObjectNode stringField = MAPPER.createObjectNode();
        stringField.put("type", "string");
        stringField.put("description", "A string parameter");
        properties.set("stringParam", stringField);
        
        // Integer 필드
        ObjectNode intField = MAPPER.createObjectNode();
        intField.put("type", "integer");
        intField.put("description", "An integer parameter");
        intField.put("minimum", 0);
        intField.put("maximum", 100);
        properties.set("intParam", intField);
        
        // Boolean 필드
        ObjectNode boolField = MAPPER.createObjectNode();
        boolField.put("type", "boolean");
        boolField.put("description", "A boolean parameter");
        properties.set("boolParam", boolField);
        
        // Array 필드
        ObjectNode arrayField = MAPPER.createObjectNode();
        arrayField.put("type", "array");
        ObjectNode items = MAPPER.createObjectNode();
        items.put("type", "string");
        arrayField.set("items", items);
        arrayField.put("description", "An array of strings");
        properties.set("arrayParam", arrayField);
        
        schema.set("properties", properties);
        
        // Required 필드
        ArrayNode required = MAPPER.createArrayNode();
        required.add("stringParam");
        schema.set("required", required);
        
        schema.put("additionalProperties", false);
        
        try {
            return MAPPER.writerWithDefaultPrettyPrinter()
                         .writeValueAsString(schema);
        } catch (Exception e) {
            return generateDefaultSchema();
        }
    }
}