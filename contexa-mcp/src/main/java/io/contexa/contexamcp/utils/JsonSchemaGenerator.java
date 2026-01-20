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


@Slf4j
@UtilityClass
public class JsonSchemaGenerator {
    
    private static final ObjectMapper MAPPER = new ObjectMapper();
    
    
    public static String generateSchema(Class<?> clazz) {
        try {
            ObjectNode schema = generateSchemaNode(clazz);
            return MAPPER.writerWithDefaultPrettyPrinter()
                         .writeValueAsString(schema);
        } catch (Exception e) {
            log.error("Failed to generate JSON schema for class: {}", clazz.getName(), e);
            
            return generateDefaultSchema();
        }
    }
    
    
    public static ObjectNode generateSchemaNode(Class<?> clazz) {
        ObjectNode schema = MAPPER.createObjectNode();
        
        
        schema.put("$schema", "http://json-schema.org/draft-07/schema#");
        schema.put("type", "object");
        
        
        JsonClassDescription classDesc = clazz.getAnnotation(JsonClassDescription.class);
        if (classDesc != null) {
            schema.put("description", classDesc.value());
        }
        
        
        ObjectNode properties = MAPPER.createObjectNode();
        ArrayNode required = MAPPER.createArrayNode();
        
        
        if (clazz.isRecord()) {
            processRecordClass(clazz, properties, required);
        } else {
            
            processRegularClass(clazz, properties, required);
        }
        
        schema.set("properties", properties);
        
        if (required.size() > 0) {
            schema.set("required", required);
        }
        
        
        schema.put("additionalProperties", false);
        
        return schema;
    }
    
    
    private static void processRecordClass(Class<?> clazz, ObjectNode properties, ArrayNode required) {
        try {
            var recordComponents = clazz.getRecordComponents();
            if (recordComponents != null) {
                for (var component : recordComponents) {
                    String fieldName = component.getName();
                    Class<?> fieldType = component.getType();
                    Type genericType = component.getGenericType();
                    
                    
                    JsonProperty jsonProperty = component.getAnnotation(JsonProperty.class);
                    if (jsonProperty != null) {
                        
                        if (!jsonProperty.value().isEmpty()) {
                            fieldName = jsonProperty.value();
                        }
                        
                        
                        if (jsonProperty.required()) {
                            required.add(fieldName);
                        }
                    }
                    
                    
                    ObjectNode fieldSchema = createFieldSchema(fieldType, genericType);
                    
                    
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
    
    
    private static void processRegularClass(Class<?> clazz, ObjectNode properties, ArrayNode required) {
        
        List<Field> allFields = getAllFields(clazz);
        
        for (Field field : allFields) {
            
            if (java.lang.reflect.Modifier.isStatic(field.getModifiers()) ||
                java.lang.reflect.Modifier.isTransient(field.getModifiers())) {
                continue;
            }
            
            String fieldName = field.getName();
            Class<?> fieldType = field.getType();
            Type genericType = field.getGenericType();
            
            
            JsonProperty jsonProperty = field.getAnnotation(JsonProperty.class);
            if (jsonProperty != null) {
                
                if (!jsonProperty.value().isEmpty()) {
                    fieldName = jsonProperty.value();
                }
                
                
                if (jsonProperty.required()) {
                    required.add(fieldName);
                }
            }
            
            
            ObjectNode fieldSchema = createFieldSchema(fieldType, genericType);
            
            
            JsonPropertyDescription propDesc = field.getAnnotation(JsonPropertyDescription.class);
            if (propDesc != null) {
                fieldSchema.put("description", propDesc.value());
            }
            
            properties.set(fieldName, fieldSchema);
        }
    }
    
    
    private static ObjectNode createFieldSchema(Class<?> fieldType, Type genericType) {
        ObjectNode schema = MAPPER.createObjectNode();
        
        
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
            
            schema.put("type", "string");
            ArrayNode enumValues = MAPPER.createArrayNode();
            for (Object constant : fieldType.getEnumConstants()) {
                enumValues.add(constant.toString());
            }
            schema.set("enum", enumValues);
        } else if (List.class.isAssignableFrom(fieldType) || Set.class.isAssignableFrom(fieldType)) {
            
            schema.put("type", "array");
            
            
            if (genericType instanceof ParameterizedType) {
                ParameterizedType paramType = (ParameterizedType) genericType;
                Type[] typeArgs = paramType.getActualTypeArguments();
                if (typeArgs.length > 0 && typeArgs[0] instanceof Class) {
                    Class<?> elementType = (Class<?>) typeArgs[0];
                    schema.set("items", createFieldSchema(elementType, elementType));
                } else {
                    
                    ObjectNode items = MAPPER.createObjectNode();
                    items.put("type", "object");
                    schema.set("items", items);
                }
            } else {
                
                ObjectNode items = MAPPER.createObjectNode();
                items.put("type", "object");
                schema.set("items", items);
            }
        } else if (Map.class.isAssignableFrom(fieldType)) {
            
            schema.put("type", "object");
            
            
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
            
            schema.put("type", "array");
            Class<?> componentType = fieldType.getComponentType();
            schema.set("items", createFieldSchema(componentType, componentType));
        } else {
            
            if (isSimpleValueClass(fieldType)) {
                
                schema.put("type", "string");
            } else {
                
                schema.put("type", "object");
                
                
                if (!fieldType.getPackage().getName().startsWith("java.")) {
                    try {
                        ObjectNode nestedSchema = generateSchemaNode(fieldType);
                        
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
    
    
    private static List<Field> getAllFields(Class<?> clazz) {
        List<Field> fields = new ArrayList<>();
        
        while (clazz != null && clazz != Object.class) {
            fields.addAll(Arrays.asList(clazz.getDeclaredFields()));
            clazz = clazz.getSuperclass();
        }
        
        return fields;
    }
    
    
    private static boolean isSimpleValueClass(Class<?> clazz) {
        return clazz.isPrimitive() ||
               clazz == String.class ||
               Number.class.isAssignableFrom(clazz) ||
               clazz == Boolean.class ||
               clazz == Character.class ||
               clazz == Date.class ||
               clazz.getName().startsWith("java.time.");
    }
    
    
    private static String generateDefaultSchema() {
        return """
            {
                "$schema": "http:
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
        schema.put("$schema", "http:
        schema.put("type", "object");
        schema.put("description", "Example tool input schema");
        
        ObjectNode properties = MAPPER.createObjectNode();
        
        
        ObjectNode stringField = MAPPER.createObjectNode();
        stringField.put("type", "string");
        stringField.put("description", "A string parameter");
        properties.set("stringParam", stringField);
        
        
        ObjectNode intField = MAPPER.createObjectNode();
        intField.put("type", "integer");
        intField.put("description", "An integer parameter");
        intField.put("minimum", 0);
        intField.put("maximum", 100);
        properties.set("intParam", intField);
        
        
        ObjectNode boolField = MAPPER.createObjectNode();
        boolField.put("type", "boolean");
        boolField.put("description", "A boolean parameter");
        properties.set("boolParam", boolField);
        
        
        ObjectNode arrayField = MAPPER.createObjectNode();
        arrayField.put("type", "array");
        ObjectNode items = MAPPER.createObjectNode();
        items.put("type", "string");
        arrayField.set("items", items);
        arrayField.put("description", "An array of strings");
        properties.set("arrayParam", arrayField);
        
        schema.set("properties", properties);
        
        
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