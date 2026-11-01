# Spring AI 1.x RAG 조사와 Contexa 반영 분석

작성: 2026-10-29. 사용자 지시: "Spring AI 공식 문서를 분석하여 RAG를 어떻게 사용 · 활용하는지 철저하게 조사하고 Contexa에 반영 · 적용해야 할 부분이 무엇인지 분석하라. 버전은 1.x이다."

**범위와 근거 등급**
- 버전: Contexa의 코어 빌드는 Spring AI BOM **1.1.8**이다. 공식 문서는 버전이 고정된 `https://docs.spring.io/spring-ai/reference/1.1/…` 경로의 7개 페이지(RAG, 벡터 DB, PGvector, ETL, 어드바이저, 임베딩, 평가, 관측)를 읽었다(페이지가 "안정 버전 2.0.2"라고 알리는 문구는 무시).
- **문서**: 공식 1.1 페이지에서 읽은 내용(페이지 요약 모델을 거쳐 이름 · 매개변수만 뽑았으므로 인용문은 원문과 대조하지 않았다). **소스**: 문서가 "다루지 않음"이라고 한 부분을 로컬 gradle 캐시의 1.1.8 소스 jar(`spring-ai-commons · model · vector-store · pgvector-store · rag · openai · ollama`)에서 직접 읽은 것. **확인**: Contexa 코드를 줄 단위로 연 것. **조사 보고**: 앞선 읽기 전용 조사 담당 보고(`기준선-RAG-정밀분석.md` 3절).

---

## 1. Spring AI 1.x가 RAG를 쓰는 방식 (공식)

### 1.1 두 가지 사용법

| 방식 | 구성 | 특징 |
|---|---|---|
| Naive RAG | `QuestionAnswerAdvisor.builder(vectorStore).searchRequest(...).promptTemplate(...)` | 검색 결과를 프롬프트 자리표시자(`query`, `question_answer_context`)에 넣음. 요청별 필터는 `.advisors(a -> a.param(QuestionAnswerAdvisor.FILTER_EXPRESSION, "type == 'Spring'"))`. `spring-ai-advisors-vector-store` 모듈 |
| Modular RAG | `RetrievalAugmentationAdvisor.builder().queryTransformers(...).queryExpander(...).documentRetriever(...).documentJoiner(...).documentPostProcessors(...).queryAugmenter(...)` | 단계별 모듈 조립. `spring-ai-rag` 모듈. 검색된 문서는 응답 문맥 키 `rag_document_context`(`RetrievalAugmentationAdvisor.DOCUMENT_CONTEXT`)에 실린다(소스) |

### 1.2 Modular RAG의 모듈 (문서 + 소스)

| 단계 | 모듈 | 핵심 매개변수 · 계약 |
|---|---|---|
| 사전 검색 | `CompressionQueryTransformer` | 대화 이력 + 후속 질문 → 독립 질의 (`.chatClientBuilder`, `.promptTemplate`) |
| | `RewriteQueryTransformer` | 장황 · 모호한 질의를 검색에 맞게 다시 씀 |
| | `TranslationQueryTransformer` | 임베딩 모델이 학습한 언어로 번역 (`.targetLanguage`) |
| | `MultiQueryExpander` | 질의 여러 개 생성 (`numberOfQueries`, `includeOriginal` 기본 true) |
| 검색 | `VectorStoreDocumentRetriever` | `vectorStore`(필수), `similarityThreshold`, `topK`, `filterExpression`(정적 · `Supplier` 동적 · 요청 문맥 `FILTER_EXPRESSION`) |
| | `DocumentJoiner` / `ConcatenationDocumentJoiner` | 여러 질의 결과 병합, 중복이면 첫 번째 유지, 점수 보존 |
| 사후 검색 | `DocumentPostProcessor` | 계약: `List<Document> process(Query, List<Document>)` (소스). 용도(문서): 중간 유실 문제, 문맥 길이 제한, 잡음 · 중복 감소, 순위 · 필터 · 압축 |
| 생성 | `ContextualQueryAugmenter` | `allowEmptyContext` **기본 false**(문맥이 비면 모델에게 "지식 밖이라 답할 수 없다"고 알리게 함), `promptTemplate`, `emptyContextPromptTemplate`. 기본 템플릿은 "Given the context information and no prior knowledge, answer the query… If the answer is not in the context, just say that you don't know."(소스) |

권고(문서 원문 요지): 질의 변환기를 쓸 때는 챗 클라이언트의 온도를 낮게(0.0) 두어 검색 품질을 올린다.

### 1.3 VectorStore · SearchRequest · 필터 (문서 + 소스)

- `VectorStore`: `add(List<Document>)`, `delete(List<String> ids)`, `delete(Filter.Expression)`, `delete(String)`, `similaritySearch(SearchRequest)`.
- `SearchRequest` 기본값: **topK 4, similarityThreshold 0.0(모두 허용)**, 범위 [0, 1], 1에 가까울수록 유사.
- 필터: `FilterExpressionBuilder`의 `eq ne gt gte lt lte in nin and or not isNull isNotNull`, 문자열 식 `"genre == 'drama' && year >= 2020"`, `in [...]`. PGvector는 이것을 PostgreSQL JSON 경로 식으로 변환한다.
- 문서 id의 멱등성 · 업서트는 문서에 없다. **소스**: `PgVectorStore`는 `INSERT … ON CONFLICT (id) DO UPDATE`로 사실상 업서트한다(문서 id가 같으면 덮어씀).
- 삭제는 id 목록 또는 필터. 버전 관리는 `docId`, `version` 같은 메타데이터로 직접 관리하라고 안내.

### 1.4 PGvector (문서 + 소스)

- 생성기 기본값: `distanceType` **COSINE_DISTANCE**, `indexType` **HNSW**, `initializeSchema` **false**, `schemaName public`, `vectorTableName vector_store`, `maxDocumentBatchSize` 10000. 인덱스 종류 `NONE / IVFFLAT / HNSW`. HNSW는 **차원 2000 이하**.
- 문서가 다루지 않는 것: HNSW 매개변수(m, ef_construction, ef_search), 임계값 의미, 필터 + 인덱스 성능 권고.
- **소스**: 임계값은 `distance = 1 − similarityThreshold`이고 질의는 `WHERE embedding <=> ? < ? … ORDER BY distance LIMIT ?`(코사인). 즉 임계값 0.5는 코사인 거리 0.5 미만. 문서의 점수는 `1.0 − distance`. Spring AI의 `PgVectorStore`는 검색 때 `ef_search`나 반복 스캔(iterative scan)을 설정하지 않는다.

### 1.5 임베딩이 무엇을 임베딩하는가 (소스로 확인한 핵심)

- 문서(`EmbeddingModel` 페이지): `getEmbeddingContent(Document)`는 기본으로 `document.getText()`를 돌려주고, "메타데이터 모드를 지원하는 구현은 `getFormattedContent(MetadataMode)`를 돌려주도록 재정의해야 한다."
- **소스(1.1.8)**:
  - `OpenAiEmbeddingModel`은 `getEmbeddingContent`를 재정의해 `document.getFormattedContent(this.metadataMode)`를 쓰고 **기본 `metadataMode = MetadataMode.EMBED`**다. `DefaultContentFormatter`는 `{metadata_string}\n\n{content}` 꼴로 메타데이터를 `key: value` 줄로 본문 앞에 붙인다(`excludedEmbedMetadataKeys`에 든 키만 제외). 즉 OpenAI 임베딩이면 **메타데이터가 임베딩 글에 들어간다.**
  - `OllamaEmbeddingModel`은 `embed(Document)`가 `document.getText()`만 쓰고 재정의가 없어 **본문만** 임베딩한다.
  - `TokenCountBatchingStrategy`의 `MetadataMode.NONE` 기본값은 배치 크기 계산(토큰 수 추정)용이며 임베딩 글을 정하지 않는다.
- ETL 페이지는 `DefaultContentFormatter`와 `MetadataMode`의 의미를 다루지 않는다(문서). 위 내용은 소스에서만 확인된다.

### 1.6 ETL · 어드바이저 · 평가 · 관측 (문서)

- ETL: `DocumentReader` / `DocumentTransformer` / `DocumentWriter`, `TokenTextSplitter`(기본 800토큰), `KeywordMetadataEnricher`(LLM이 키워드를 `excerpt_keywords`에), `SummaryMetadataEnricher`(LLM이 요약을 메타데이터에). 둘 다 LLM 호출 비용이 든다.
- 어드바이저 API: `CallAdvisor` / `StreamAdvisor`, `getOrder()`(작을수록 요청에서 먼저, 응답에서 나중), 요청별 파라미터 `.advisors(a -> a.param(...))`, 내장 어드바이저(`QuestionAnswerAdvisor`, `RetrievalAugmentationAdvisor`, `SafeGuardAdvisor` 등). RAG · 기억 · 가드의 상대 순서 지침은 **문서에 없다**.
- 평가: `Evaluator.evaluate(EvaluationRequest(userText, List<Content> dataList, responseContent))`. `RelevancyEvaluator`는 응답이 검색 문맥과 일치하는지 YES/NO(기본 프롬프트가 원문으로 제공됨), `FactCheckingEvaluator`는 `Document: {document} Claim: {claim}` 형식으로 주장이 문맥에 의해 뒷받침되는지 검사(작은 Minicheck 모델 권장). RAG 품질 테스트에 `RetrievalAugmentationAdvisor.DOCUMENT_CONTEXT`를 `dataList`로 넘기는 예가 있다.
- 관측: `VectorStore`, `EmbeddingModel`, `ChatClient`(어드바이저 포함), 도구 호출이 계측된다. 벡터 저장소 지표 `db.vector.client.operation`(`db.operation.name` = add/delete/query, `db.system` = `pg_vector` …), 고카디널리티 키 `db.vector.query.content`, `…filter`, `…top_k`, `…similarity_threshold`. 검색 응답 내용 기록은 `spring.ai.vectorstore.observations.log-query-response`(기본 false)이며 민감 정보 노출 위험 경고가 있다.

---

## 2. Contexa 현황과 대응

| Spring AI 기능 | Contexa 현재 | 비교 판단 |
|---|---|---|
| RAG 어드바이저 (Naive · Modular) | 코어 `build.gradle`이 `spring-ai-rag`와 `spring-ai-advisors-vector-store`를 선언(확인). 그러나 `RetrievalAugmentationAdvisor` · `VectorStoreDocumentRetriever` · `QueryTransformer`를 쓰는 파일은 `CoreRAGAutoConfiguration` **하나뿐**(확인). **판정 경로(1 · 2층 선례 조회)는 자체 구현** | 자체 구현은 사용자 격리 · 세션 제외 · 학습 상태 · 권한 필터가 필요해서 타당. 단 어드바이저 빈에 **userId 필터가 없다**(조사 보고 R15) |
| `SearchRequest` · 필터 DSL | v19 경로가 사용, 한도 12/5 · 임계값 0.5 · 필터 6종(확인/조사 보고) | Spring 의미와 같다. 임계값 0.5 = 코사인 거리 < 0.5 |
| 동적 필터(`Supplier` · 요청 문맥) | 요청마다 필터를 만들어 직접 전달 | 같은 효과 |
| `QueryTransformer` · `MultiQueryExpander` | v19 다중 질의(광범위 · 기준선 · 보조)는 설정으로 켤 때만, 규칙 기반(조사 보고) | LLM 변환이 없어 지연 없음. 공식 권고(온도 0.0)는 해당 없음 |
| `DocumentPostProcessor` | 자체: 순위 `PastRecordRanking`, 같은 사실 묶기, 줄 상한 5, 권한 필터, 주입 방어 | 계약 이식 시 교체 · 시험이 쉬워짐(선택) |
| `ContextualQueryAugmenter` 빈 문맥 | 공식은 "문맥이 비면 답하지 마라". Contexa는 빈 선례를 정상 상태로 두고 "검색된 문서 증거가 있다고 가정하지 마라" 문구를 둠(조사 보고) | 판정 용도에 맞는 반대 선택. 타당 |
| PGvector 생성기 | `initialize-schema` 기본 **true**(확인 `ContexaDefaultPropertiesPostProcessor.java:52`가 기본 속성으로 주입, `CoreRAGAutoConfiguration.java:145`가 그 값을 조건으로 사용), HNSW · 코사인, `hnsw.m` · `efConstruction` 설정은 소비처 없음(R15), `efSearch` · 반복 스캔 · 정확 검색(개인 검색)은 자체 설정 | 공식 기본 `initializeSchema=false`와 반대. 운영 스키마는 마이그레이션 관리가 맞다. 쓰이지 않는 인덱스 설정은 정리 |
| 임베딩 대상 글 | 쓰기: 본문(약 100자)만 의도(조사 보고). 실제는 **제공자에 따라 다름**: OpenAI = 메타데이터 포함(EMBED), Ollama = 본문만(소스) | **불일치 위험**(아래 3절 S-2) |
| 임베딩 사용처 | v21 판정 경로의 선례 조회는 **임베딩 없이 SQL**(확인 `AbstractTieredStrategy.java:796-797`: `readsPastRecordsExactly` → `searchPastRecordsExactly`, `similaritySearch`는 그 아래 v19 경로). `similaritySearch` 호출처는 `VectorStoreCacheLayer`(v19), `ContextRetriever`, `AbstractVectorLabService`, `PgVectorSearchSettings`, `UnifiedVectorService`(확인) | v21 판정에서는 쓰기마다 임베딩을 만들지만 조회에 쓰이지 않는다(S-1) |
| 업서트 · 문서 id | `UUID.nameUUIDFromBytes(documentType:eventId)` + 라이브러리 `ON CONFLICT DO UPDATE`(확인) | 공식 권고 없음. Contexa가 더 엄격 |
| 삭제 by 필터 | 사용자 정리 단계가 `vectorStore.delete(userId == X)`(확인) | 공식 API 그대로 |
| 관측 지표 | Spring AI 벡터 저장소 지표 활성 여부 미확인. 자체 지표는 `check_guard_health` 수준 | S-5 |
| 평가기(`RelevancyEvaluator` · `FactCheckingEvaluator`) | 자체 `FactAccuracyCheck`(사실 줄이 컨텍스트와 맞는지) | S-6 |
| Spring AI 버전 | 코어 서브프로젝트 `implementation platform(…bom:1.1.8)`, **시작 모듈 `api platform(…bom:1.1.2)`**, `contexa-iam` 시험 픽스처도 1.1.2(확인) | S-8 |

---

## 3. 반영 · 적용할 부분 (우선순위)

| ID | 우선 | 내용 | 근거 | 연결 |
|---|---|---|---|---|
| S-1 | **높음** | **v21 판정 경로의 쓰기에서 임베딩을 분리**: 선례 조회가 SQL이므로 판정마다 임베딩을 동기로 만들 필요가 없다. 임베딩이 필요한 소비자(v19, `ContextRetriever`)가 있을 때만 만들거나 지연 · 배치로 만든다. 임베딩 서버 지연 때문에 학습 기록이 15초 제한으로 유실되던 문제(142건 중 57건)와 쓰기 지연을 함께 해소 | 확인: v21 조회에 임베딩 없음(`AbstractTieredStrategy.java:796-797`). 실측: 가드 임베딩 요청 1,548건이 모두 쓰기 쪽(`기준선-RAG-정밀분석.md` 189행), 임베딩 지연으로 저장 실패 57건/판정 142건(`공인-벤치마크-구현계획.md` v2.3, 임베딩 분리 전 실행) | QF-8 · BR-C4 |
| S-2 | **높음** | **임베딩 글의 명시적 통제**: `getEmbeddingContent`가 제공자마다 다르므로 문서에 `ContentFormatter`(`excludedEmbedMetadataKeys` 전체 또는 의도한 키만)를 붙여 어느 제공자에서도 같은 글이 임베딩되게 한다. 제공자를 바꾼 저장소(OpenAI → Ollama 전환 이력: 위임결정기록 DD-4)에서 서로 다른 임베딩 공간이 섞이지 않게 임베딩 모델 식별자를 메타데이터에 기록하고 불일치 시 경고 | 소스: OpenAI EMBED vs Ollama 본문만. 쇼케이스 벡터 문서에 두 제공자가 섞였는지는 **미확인**(메타데이터에 모델 식별자가 없을 수 있음) | QF-13 |
| S-3 | **높음** | **BOM 버전 통일**: 시작 모듈이 소비자에게 `api platform(…1.1.2)`를 전이시켜 코어가 1.1.8로 시험 · 컴파일된 것과 다른 라이브러리가 운영에서 쓰일 수 있다. 게시 POM의 실제 제약을 확인하고 한 버전으로 맞춘다 | 확인: `spring-boot-starter-contexa/build.gradle:10` 대 루트 `build.gradle:128` | 신규 |
| S-4 | 중 | 선례 후처리(순위 · 묶기 · 상한 · 권한 필터)를 `DocumentPostProcessor` 계약으로 감싸 교체 가능 · 단위 시험 가능하게 한다. 동작 변경 없음(리팩터링) | 공식 계약 | BR-C6 |
| S-5 | 중 | Spring AI 벡터 저장소 관측(`db.vector.client.operation`)을 켜고 Contexa의 학습 유실 · 재시도 지표(QF-12)를 같은 레지스트리에 노출. `log-query-response`는 기본 false 유지(민감 정보 경고) | 문서 | QF-8 · 12 |
| S-6 | 중 | 평가: LQ-4(선례 관련성)와 CQ-1(인자 출처 사실이 맞는가) 시험에 `RelevancyEvaluator` · `FactCheckingEvaluator` 방식의 LLM 판정기를 보조로 쓴다(Haiku, 자체 패널과 병행) | 문서 | BR-M4 |
| S-7 | 중 | `CoreRAGAutoConfiguration.behaviorAnalysisRagAdvisor`(userId 필터 없음, 판정 경로에서 안 쓰임)를 제거하거나 사용자 격리 필터를 강제 | 조사 보고 R15 | BR-D1 |
| S-8 | 낮음 | 쓰이지 않는 PGvector 속성(`hnsw.m`, `efConstruction`, `ivfflat.*`)을 실제 인덱스 생성에 반영하거나 삭제. `initialize-schema` 기본값과 운영 스키마 관리 안내 | 문서 + R15 | BR-C7 |
| S-9 | 낮음 | 질의 변환 · 확장은 v19 다중 질의를 쓸 때만 해당. 쓰게 되면 공식 권고(온도 0.0)를 따른다. Anthropic Haiku 5.5는 온도 지정을 거부하므로 변환기 모델은 별도 선택 | 문서 + 실측 | 해당 없음(보류) |

**하지 않는 것**: 판정 경로를 `RetrievalAugmentationAdvisor`로 통째로 옮기는 것. 사용자 격리 · 학습 상태 제외 · 권한 필터 · 주입 방어 · 선례 줄 형식(12필드) 같은 Contexa의 요구가 어드바이저의 일반 틀에 들어가지 않고, 판정은 "답 생성"이 아니라 "증거 제공"이기 때문이다.

---

## 4. 확인하지 못한 것

- 쇼케이스 D의 실제 임베딩 제공자 이력과 벡터 문서의 임베딩 일관성(메타데이터에 모델 식별자 없음). 쇼케이스 DB의 벡터를 두 제공자 값으로 구분하는 방법은 아직 없다(S-2의 선행 조사).
- ~~시작 모듈 BOM 1.1.2가 게시된 POM에서 소비자에게 실제로 적용되는지(S-3)~~ → **확인(2026-10-29)**: `generatePomFileForMavenJavaPublication`이 만든 `spring-boot-starter-contexa/build/publications/mavenJava/pom-default.xml`의 `dependencyManagement`에 `spring-ai-bom:1.1.2`가 `import`로 들어 있다. 소비자가 시작 모듈과 Spring AI 제공자 시작 모듈을 버전 없이 쓰면 1.1.2가 적용되고, 코어는 1.1.8로 컴파일 · 시험되었다. 1.1.2와 1.1.8 사이의 동작 차이는 확인하지 않았다.
- 공식 문서 7페이지는 요약 모델을 거쳤으므로 문구 수준의 인용은 확정이 아니다. 클래스 · 매개변수 이름은 소스 확인된 항목만 "소스"로 표시했다.
