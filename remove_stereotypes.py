import os
import re
from pathlib import Path

# contexa-iam 소스 디렉토리
iam_src_dir = Path(r"d:\projects\contexa\contexa-iam\src\main\java")

# 제거할 어노테이션 패턴
stereotype_annotations = [
    "@Service",
    "@Component",
    "@Controller",
    "@RestController"
]

# import 패턴
import_patterns = [
    "import org.springframework.stereotype.Service;",
    "import org.springframework.stereotype.Component;",
    "import org.springframework.stereotype.Controller;",
    "import org.springframework.web.bind.annotation.RestController;"
]

def remove_stereotypes_from_file(file_path):
    """파일에서 stereotype 어노테이션 제거"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        original_content = content
        modified = False

        # 어노테이션 라인 제거 (줄 전체 제거)
        lines = content.split('\n')
        new_lines = []

        for line in lines:
            stripped = line.strip()
            # stereotype 어노테이션이 있는 줄은 제거
            if any(stripped == anno or stripped.startswith(anno + '(') for anno in stereotype_annotations):
                modified = True
                continue
            # import문 제거
            elif any(stripped == imp for imp in import_patterns):
                modified = True
                continue
            else:
                new_lines.append(line)

        if modified:
            # 파일 저장
            new_content = '\n'.join(new_lines)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            return True

        return False

    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def main():
    """모든 Java 파일 처리"""
    modified_count = 0
    total_count = 0

    # 모든 .java 파일 찾기
    for java_file in iam_src_dir.rglob("*.java"):
        total_count += 1
        if remove_stereotypes_from_file(java_file):
            modified_count += 1
            print(f"Modified: {java_file.relative_to(iam_src_dir)}")

    print(f"\n총 {total_count}개 파일 중 {modified_count}개 파일 수정 완료")

if __name__ == "__main__":
    main()
