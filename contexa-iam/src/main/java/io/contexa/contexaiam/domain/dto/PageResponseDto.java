package io.contexa.contexaiam.domain.dto;

import lombok.Getter;
import org.springframework.data.domain.Page;
import java.util.List;

/**
 * API 응답에서 페이징된 결과를 안정적인 JSON 구조로 반환하기 위한 전용 DTO.
 * Spring Data의 Page 객체를 래핑합니다.
 * @param <T> 페이징된 컨텐츠의 타입
 */
@Getter
public class PageResponseDto<T> {

    private final List<T> content;
    private final int pageNumber;
    private final int pageSize;
    private final long totalElements;
    private final int totalPages;
    private final boolean isLast;

    public PageResponseDto(Page<T> page) {
        this.content = page.getContent();
        this.pageNumber = page.getNumber();
        this.pageSize = page.getSize();
        this.totalElements = page.getTotalElements();
        this.totalPages = page.getTotalPages();
        this.isLast = page.isLast();
    }
}