package io.contexa.contexaiam.admin.web.studio.dto;

/**
 * 접근 경로를 구성하는 개별 노드(사용자, 그룹, 역할 등)를 표현하는 DTO 입니다.
 */
public record AccessPathNode(
        String type, // "사용자", "그룹", "역할", "권한"
        String name,
        String description
) {}