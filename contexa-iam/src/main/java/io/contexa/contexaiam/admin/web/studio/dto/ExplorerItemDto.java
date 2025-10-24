package io.contexa.contexaiam.admin.web.studio.dto;

/**
 * Authorization Studio의 Explorer 패널에 표시될 아이템을 위한 DTO 입니다.
 * @param id 엔티티의 고유 ID
 * @param name 사용자에게 표시될 이름
 * @param type 아이템 타입 ("USER", "GROUP", "PERMISSION", "POLICY")
 * @param description 부가적인 설명 (예: 이메일, 그룹 설명 등)
 */
public record ExplorerItemDto(Long id, String name, String type, String description) {}
