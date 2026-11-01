# Builds the UX-R1 screen design deck (16:9, every text 14pt or larger) from the mockup screenshots.
import json, math, pathlib, sys
from PIL import Image
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.oxml.ns import qn
from lxml import etree

ROOT = pathlib.Path(__file__).resolve().parent
MOCK = ROOT.parent / 'mock'
OUT = MOCK / 'out'
AUD = ROOT.parent / 'audit' / 'run'
IMG = ROOT / 'img'; IMG.mkdir(exist_ok=True)
RECTS = json.loads((ROOT / 'rects.json').read_text(encoding='utf-8'))
RECTS.update(json.loads((ROOT / 'rects2.json').read_text(encoding='utf-8')))
TARGET = pathlib.Path(sys.argv[1])

C = dict(bg='0A0F1C', side='0C1322', surface='101828', s2='151F33', s3='1A263E', line='1E2A42', line2='2A3A5A',
         text='E9EDF5', t2='B3BDD0', t3='8592AB', brand='E6B84F', ink='1A1300', link='7FA6FF',
         allow='2BC48A', stepup='F2A93B', hold='A98BFF', block='F25F6B', none='94A0B8')
FONT, MONO = 'Malgun Gothic', 'Consolas'
W, H = 13.333, 7.5

prs = Presentation(); prs.slide_width = Inches(W); prs.slide_height = Inches(H)
BLANK = prs.slide_layouts[6]
slides_meta = []
WARN = []


def rgb(h): return RGBColor.from_string(h)


def style(run, size=14, color='text', bold=False, mono=False):
    assert size >= 14, size
    f = run.font; f.size = Pt(size); f.bold = bold; f.color.rgb = rgb(C.get(color, color)); f.name = MONO if mono else FONT
    rPr = run._r.get_or_add_rPr()
    ea = rPr.find(qn('a:ea'))
    if ea is None: ea = etree.SubElement(rPr, qn('a:ea'))
    ea.set('typeface', MONO if mono else FONT)


def text(slide, x, y, w, h, parts, size=14, color='text', bold=False, align=None, anchor=None, spacing=1.15, mono=False):
    """parts: str | list of paragraphs; a paragraph is str or list of (text, opts) runs."""
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h)); tf = tb.text_frame
    tf.word_wrap = True; tf.margin_left = tf.margin_right = Inches(0); tf.margin_top = tf.margin_bottom = Inches(0)
    if anchor: tf.vertical_anchor = anchor
    paras = parts if isinstance(parts, list) else [parts]
    for i, p in enumerate(paras):
        para = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        para.line_spacing = spacing
        if align: para.alignment = align
        runs = p if isinstance(p, list) else [(p, {})]
        for t, o in runs:
            r = para.add_run(); r.text = t
            style(r, o.get('size', size), o.get('color', color), o.get('bold', bold), o.get('mono', mono))
    est = 0
    for p in paras:
        runs = p if isinstance(p, list) else [(p, {})]
        t = ''.join(r[0] for r in runs); sz = max([r[1].get('size', size) for r in runs] or [size])
        est += est_lines(t, w, sz) * sz / 72 * 1.2 * spacing
    if est > h + 0.35 and y + est > 6.95: WARN.append(f'slide {len(slides_meta)} text box bottom {y + est:.2f}in: {str(paras[0])[:40]}')
    return tb


def rect(slide, x, y, w, h, fill='surface', line=None, radius=None, shape=MSO_SHAPE.RECTANGLE):
    sh = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE if radius is not None else shape, Inches(x), Inches(y), Inches(w), Inches(h))
    if fill: sh.fill.solid(); sh.fill.fore_color.rgb = rgb(C.get(fill, fill))
    else: sh.fill.background()
    if line: sh.line.color.rgb = rgb(C.get(line, line)); sh.line.width = Pt(1)
    else: sh.line.fill.background()
    if radius is not None: sh.adjustments[0] = radius
    sh.shadow.inherit = False
    return sh


def label_shape(sh, t, size=14, color='text', bold=True):
    tf = sh.text_frame; tf.margin_left = tf.margin_right = Inches(0.04); tf.margin_top = tf.margin_bottom = Inches(0)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE; p = tf.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
    r = p.add_run(); r.text = t; style(r, size, color, bold)


def new_slide(kicker, title, sub=None):
    s = prs.slides.add_slide(BLANK)
    s.background.fill.solid(); s.background.fill.fore_color.rgb = rgb(C['bg'])
    rect(s, 0.5, 0.5, 0.07, 0.42, 'brand')
    text(s, 0.72, 0.18, 9, 0.3, kicker, 14, 't3', True)
    text(s, 0.72, 0.44, 11.9, 0.55, title, 26, 'text', True)
    if sub: text(s, 0.72, 1.02, 11.9, 0.4, sub, 15, 't2')
    slides_meta.append(s)
    return s


def footer_all():
    n = len(slides_meta)
    for i, s in enumerate(slides_meta, 1):
        if i == 1: continue
        rect(s, 0.5, 7.0, W - 1.0, 0.01, 'line')
        text(s, 0.5, 7.06, 9, 0.3, 'Contexa · 데모 화면 전면 개선 설계안 (UX-R1 v3) · 2026-11-01', 14, 't3')
        text(s, W - 2.5, 7.06, 2.0, 0.3, f'{i} / {n}', 14, 't3', align=PP_ALIGN.RIGHT)


def est_lines(t, width_in, size=14):
    if not t: return 1
    lines = 0
    for seg in str(t).split('\n'):
        units = sum(1.0 if ord(ch) > 0x2E80 else 0.56 for ch in seg)
        lines += max(1, math.ceil(units * size / 72 * 1.02 / max(width_in, 0.3)))
    return lines


def table(slide, x, y, widths, rows, header=True, size=14, mono_cols=(), color_cols=None, max_h=None):
    """Draws one table; returns the height used. rows[0] is the header."""
    n, m = len(rows), len(widths)
    shp = slide.shapes.add_table(n, m, Inches(x), Inches(y), Inches(sum(widths)), Inches(0.4 * n))
    tbl = shp.table; tblPr = tbl._tbl.tblPr
    sid = tblPr.find(qn('a:tableStyleId'))
    if sid is None: sid = etree.SubElement(tblPr, qn('a:tableStyleId'))
    sid.text = '{2D5ABB26-0587-4C30-8999-92F81FD0307C}'
    for j, wd in enumerate(widths): tbl.columns[j].width = Inches(wd)
    total = 0
    for i, row in enumerate(rows):
        hdr = header and i == 0
        lines = max(est_lines(row[j], widths[j] - 0.2, size) for j in range(m))
        rh = 0.14 + 0.27 * lines; tbl.rows[i].height = Inches(rh); total += rh
        for j in range(m):
            cell = tbl.cell(i, j); cell.fill.solid()
            cell.fill.fore_color.rgb = rgb(C['s2'] if hdr else (C['surface'] if i % 2 else '0D1424'))
            cell.margin_left = cell.margin_right = Inches(0.1); cell.margin_top = cell.margin_bottom = Inches(0.05)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            tf = cell.text_frame; tf.word_wrap = True; p = tf.paragraphs[0]
            r = p.add_run(); r.text = str(row[j])
            col = 't3' if hdr else ('text' if j == 0 else 't2')
            if color_cols and not hdr and j in color_cols: col = color_cols[j]
            style(r, size, col, hdr or j == 0, (j in mono_cols) and not hdr)
    if y + total > 6.9: WARN.append(f'slide {len(slides_meta)} table bottom {y + total:.2f}in')
    return total


def paged_table(kicker, title, sub, widths, rows, x=0.6, y=1.55, max_h=5.25, **kw):
    head, body = rows[0], rows[1:]
    pages, cur, h = [], [], 0.14 + 0.27 * max(est_lines(head[j], widths[j] - 0.2) for j in range(len(widths)))
    base = h
    for r in body:
        rh = 0.14 + 0.27 * max(est_lines(r[j], widths[j] - 0.2) for j in range(len(widths)))
        if cur and h + rh > max_h: pages.append(cur); cur, h = [], base
        cur.append(r); h += rh
    if cur: pages.append(cur)
    for k, pg in enumerate(pages, 1):
        t = title + (f' ({k}/{len(pages)})' if len(pages) > 1 else '')
        s = new_slide(kicker, t, sub)
        table(s, x, y, widths, [head] + pg, **kw)


def crop(src, top_css=0, bottom_css=None, scale=2, out=None, width=2200):
    im = Image.open(src); b = im.height if bottom_css is None else min(im.height, int(bottom_css * scale))
    im = im.crop((0, int(top_css * scale), im.width, b))
    if im.width > width: im = im.resize((width, round(im.height * width / im.width)), Image.LANCZOS)
    import os
    if os.environ.get('LIGHT') == '1':
        lw = min(width, 1600)
        if im.width > lw: im = im.resize((lw, round(im.height * lw / im.width)), Image.LANCZOS)
        p = IMG / ((out or (pathlib.Path(src).stem + f'-{top_css}-{bottom_css}.png')).rsplit('.', 1)[0] + '.jpg'); im.convert('RGB').save(p, quality=88, optimize=True); return p, im.size
    p = IMG / (out or (pathlib.Path(src).stem + f'-{top_css}-{bottom_css}.png')); im.save(p, optimize=True); return p, im.size


def marker(slide, x, y, n):
    sh = rect(slide, x, y, 0.34, 0.34, 'brand', 'bg', shape=MSO_SHAPE.OVAL); label_shape(sh, str(n), 14, 'ink', True)


def screen_slide(kicker, title, sub, f, notes, top=0, bottom=None):
    s = new_slide(kicker, title, sub)
    page_h = RECTS[f]['pageH']; bottom = bottom or page_h
    src = OUT / f.replace('.html', '-1440.png')
    p, (pw, ph) = crop(src, top, bottom, out=f.replace('.html', f'-{top}.png'))
    css_h = bottom - top; box_w, box_h = 7.4, 5.3
    sc = min(box_w / 1440, box_h / css_h); iw, ih = 1440 * sc, css_h * sc
    x0, y0 = 0.6, 1.55
    rect(s, x0 - 0.03, y0 - 0.03, iw + 0.06, ih + 0.06, None, 'line2')
    s.shapes.add_picture(str(p), Inches(x0), Inches(y0), Inches(iw), Inches(ih))
    px = x0 + iw + 0.35; pw_in = W - 0.5 - px
    yy = y0
    for i, (sel, head, desc) in enumerate(notes, 1):
        r = RECTS[f]['rects'][sel]
        if r and top <= r[1] < bottom:
            marker(s, x0 + r[0] * sc - 0.1, y0 + (r[1] - top) * sc - 0.1, i)
        rect(s, px, yy + 0.02, 0.34, 0.34, 'brand', shape=MSO_SHAPE.OVAL); label_shape(s.shapes[-1], str(i), 14, 'ink', True)
        text(s, px + 0.46, yy, pw_in - 0.46, 0.3, head, 15, 'text', True)
        dl = est_lines(desc, pw_in - 0.46)
        text(s, px + 0.46, yy + 0.33, pw_in - 0.46, 0.27 * dl, desc, 14, 't2', spacing=1.1)
        yy += 0.4 + 0.27 * dl + 0.1
    if yy > 6.9: WARN.append(f'slide {len(slides_meta)} notes end {yy:.2f}in ({f})')
    return s


def two_images(kicker, title, sub, a, b, cap_a, cap_b, a_crop=(0, 900), b_crop=(0, 900), a_scale=2, b_scale=2):
    s = new_slide(kicker, title, sub)
    for k, (src, cap, (t, bt), scl) in enumerate([(a, cap_a, a_crop, a_scale), (b, cap_b, b_crop, b_scale)]):
        p, (pw, ph) = crop(src, t, bt, scale=scl, out=f'{pathlib.Path(src).stem}-{k}-{t}-{bt}.png')
        iw = 5.95; ih = iw * ph / pw; x = 0.6 + k * 6.25; y = 1.6
        rect(s, x - 0.03, y - 0.03, iw + 0.06, ih + 0.06, None, 'line2')
        s.shapes.add_picture(str(p), Inches(x), Inches(y), Inches(iw), Inches(ih))
        text(s, x, y + ih + 0.15, iw, 1.4, cap, 14, 't2', spacing=1.1)
    return s


# ---------------------------------------------------------------- 1 cover
s = prs.slides.add_slide(BLANK); slides_meta.append(s)
s.background.fill.solid(); s.background.fill.fore_color.rgb = rgb(C['bg'])
p, (pw, ph) = crop(OUT / 's-overview-1440.png', 0, 900, out='cover.png')
s.shapes.add_picture(str(p), Inches(6.2), Inches(1.2), Inches(6.7), Inches(6.7 * ph / pw))
rect(s, 0.6, 1.25, 0.07, 1.25, 'brand')
text(s, 0.85, 1.15, 5.3, 0.4, 'CONTEXA · LIVE DEMO', 15, 'brand', True)
text(s, 0.85, 1.55, 5.3, 1.6, ['데모 화면 전면 개선', '화면 설계안'], 34, 'text', True, spacing=1.05)
text(s, 0.85, 3.35, 5.1, 1.2, '데모 시작 · 안내형 체험 흐름 · 보안 업무 용어 · 표준 벤치마크를 중심으로 한 전면 개편(UX-R1 v3)', 16, 't2')
text(s, 0.85, 4.75, 5.1, 1.5, [[('작성 ', {'color': 't3'}), ('2026-10-31 · v3 2026-11-01', {})], [('상태 ', {'color': 't3'}), ('사용자 승인 대기', {})], [('근거 ', {'color': 't3'}), ('docs/showcase/데모-화면-전면개선-기획안.md', {'mono': True, 'size': 14})]], 15, 'text')

# ---------------------------------------------------------------- 2 contents
s = new_slide('목차', '구성')
items = [('1', '지시와 목표', '사용자 지시 8개와 산출물'), ('2', '현행 분석', '256캡처 전수 측정, 눈 검수, 지금 대 바뀐 뒤 7쌍'),
         ('3', '원칙 · 정보 구조', '원칙 11개, 방문자 동선 순서의 메뉴 5묶음 13개'),
         ('4', '화면 틀 · 디자인 체계', '공통 틀, 요소 규격, 글자 9단계, 색 · 뱃지 · 대비'),
         ('5', '체험 흐름 (v3)', '데모 시작 · 1단계 · 2~4단계 · 같은 요청 비교, 원칙 9개'),
         ('6', '화면별 설계', '결과 분석 · 검증 · 도입 화면, 요소 번호 주석'),
         ('7', '휴대폰 · 라이트 · 영어', '390 첫 화면, 라이트 테마, 영어판'),
         ('8', '표준 벤치마크 · 용어 · 문체', '공인 결과 구분, 용어 체계, 문체, 64화면 제목'),
         ('9', '검증 · 구현 · 결정', '숫자 출처, 고친 오류, 구현 단계, 결정 19개')]
for i, (n, t, d) in enumerate(items):
    col, row = i % 3, i // 3; x = 0.6 + col * 4.1; y = 1.55 + row * 1.75
    rect(s, x, y, 3.85, 1.55, 'surface', 'line', radius=0.06)
    text(s, x + 0.25, y + 0.2, 0.6, 0.4, n, 22, 'brand', True)
    text(s, x + 0.8, y + 0.22, 2.9, 0.4, t, 17, 'text', True)
    text(s, x + 0.25, y + 0.72, 3.4, 0.8, d, 14, 't2', spacing=1.1)

# ---------------------------------------------------------------- 3 directive
s = new_slide('1 · 지시와 목표', '사용자 지시와 이 설계안의 산출물', '2026-10-31 지시 원문 요지 — 모든 항목을 설계에 반영했다')
dirs = ['메뉴를 왼쪽으로. 메뉴마다 독립 화면. 실제 데모 실행 화면만 단계 버튼, 결과 · 통계 · 조회는 탭으로 바로 찾아간다',
        '참고 화면(그누보드7 관리 화면)보다 훨씬 고급스럽고 분명하게. 영감만 받고 베끼지 않는다',
        '모달 · 펼치기는 필요할 때만. 중요한 것은 바로 보이되 어지럽거나 지루하지 않게',
        '텍스트 · 도형 · 버튼 · 여백까지 정밀하게. 글로벌 커뮤니티의 첫 단추 — 전문성과 실용성',
        '벤치마크는 자체 측정과 contexa-benchmark(공인 표준)를 나눠 전문적으로. 공인 결과는 매우 중요한 자산',
        '메뉴 이름과 모든 설명 · 소개 · 제목 · 질문을 보안 비즈니스 용어로',
        '분석과 기획이 끝나면 화면 설계안을 pptx로',
        '(v3) 관리 페이지 성격을 버리고, 데모 시작 · 1단계 · 체험 흐름을 기존보다 훨씬 뛰어나게']
for i, d in enumerate(dirs):
    y = 1.6 + i * 0.6
    rect(s, 0.6, y, 0.4, 0.4, 's3', radius=0.2); label_shape(s.shapes[-1], str(i + 1), 14, 'text', True)
    text(s, 1.15, y + 0.04, 6.9, 0.6, d, 14, 'text', spacing=1.05)
rect(s, 8.45, 1.6, 4.35, 4.4, 'surface', 'line', radius=0.04)
text(s, 8.7, 1.8, 3.9, 0.4, '산출물', 17, 'text', True)
text(s, 8.7, 2.3, 3.95, 3.6, [[('기획안 v2', {'bold': True})], [('docs/showcase/데모-화면-전면개선-기획안.md', {'mono': True, 'color': 't2'})], '',
                              [('정지 시안 25개 파일', {'bold': True})], [('v3 체험 흐름 8 + 분석 · 검증 · 도입 화면 · 한 · 영 · 라이트 · 390', {'color': 't2'})], [('docs/showcase/ux-r1-시안/', {'mono': True, 'color': 't2'})], '',
                              [('화면 설계안(이 문서)', {'bold': True})], [('기획안 19절의 결정 19개 승인 요청', {'color': 't2'})]], 14, 'text', spacing=1.1)

# ---------------------------------------------------------------- 4 analysis numbers
s = new_slide('2 · 현행 분석', '현행 화면 전수 측정 — 64화면 × 한 · 영 × 1440 · 390 = 256캡처', 'Playwright 자동 측정 + 1440 원래 해상도 눈 검수. 같은 도구로 시안도 측정해 비교했다')
tiles = [('20px', '5,672회', '글자 11종 중 20px가 거의 전부 — 위계 없음'), ('30종', '버튼 높이', '11px~118px. 세로 간격도 31종'),
         ('59개', '접기', '25화면에서 판정 근거 · 수치를 접어 둠'), ('29 / 64', '질문 · 지시형 제목', '"…막았을까요?" 22개, "…선택하세요" 7개'),
         ('69개', '내용 없이 넓은 상자', '44화면 — 카드 절반이 빈칸'), ('544회', '"판단" 사용', '보안 업무 용어 대신 일상어("다섯 보안" 34 · "평소" 291)')]
for i, (big, k, d) in enumerate(tiles):
    col, row = i % 3, i // 3; x = 0.6 + col * 4.1; y = 1.65 + row * 2.6
    rect(s, x, y, 3.85, 2.35, 'surface', 'line', radius=0.05)
    text(s, x + 0.3, y + 0.25, 3.3, 0.4, k, 15, 't3', True)
    text(s, x + 0.3, y + 0.65, 3.3, 0.8, big, 36, 'text', True)
    text(s, x + 0.3, y + 1.5, 3.3, 0.8, d, 14, 't2', spacing=1.1)

# ---------------------------------------------------------------- 5 before/after numbers
paged_table('2 · 현행 분석', '수치 비교 — 현행 대 시안', '시안은 같은 측정 도구로 한국어 1440 14화면을 쟀다',
            [3.0, 4.6, 4.5], [
                ['항목', '현행(64화면)', '시안'],
                ['글자 크기 종류', '11종, 20px가 5,672회', '9종(12 · 13 · 14 · 15 · 16 · 18 · 24 · 28 · 32)'],
                ['크기 · 굵기 조합', '21', '19(로고 2 포함)'],
                ['굵게(700)', '4,172회 — 본문 대부분', '제목 · 큰 수치 · 로고만'],
                ['버튼 · 링크 높이', '30종', '3종(32 · 36 · 44)'],
                ['세로 간격', '31종(1 · 7 · 9 · 13 · 17 · 21 …)', '4px 격자 값만'],
                ['모서리', '6종(0 · 6 · 10 · 14 · 20 · 999)', '6종 토큰(4 · 6 · 8 · 12 · 원 · 알약)'],
                ['대비 부족 글', '36건(빨간 막대 위, 1.01:1)', '토큰 계산값 모두 4.5:1 이상'],
                ['접기', '59개 · 25화면', '0'],
                ['내용 없이 넓은 상자', '69개 · 44화면', '0'],
                ['휴대폰 쪽 높이', '중앙 1,197px · 최대 5,356px', '첫 화면에 결론 · 주 동작'],
                ['카드 밖 넘침', 'VP-12 수정 이력 다수', '0(17화면 × 1440 · 390 자동 검사)']])

# ---------------------------------------------------------------- 6-7 problems
paged_table('2 · 현행 분석', '현행 화면의 문제', '근거는 측정값과 눈 검수 사진(기획안 1.3절)', [0.75, 6.25, 5.1], [
    ['#', '문제', '근거'],
    ['E-1', '메뉴가 숨어 있다 — "메뉴" 버튼 → 모달 7개, 지금 위치 표시 없음', 'AppHeader.tsx'],
    ['E-2', '모든 것이 한 줄 흐름 — 찾아보는 화면까지 이전 · 다음으로 지나감', 'route.json, 64화면'],
    ['E-3', '글자 위계 없음 — 본문 · 보조 · 표 · 칩 모두 20px, 굵게 4,172회', '자동 측정'],
    ['E-4', '중요한 것이 접혀 있음 — 판정 이유 원문, 나간 문서 수, 일곱 단계 값', '접기 59개'],
    ['E-5', '화면 틀이 셋 — 바닥 고정 막대 · 가운데 정렬 · 912px 기둥', '눈 검수'],
    ['E-6', '다시 찾아갈 수 없음 — 실행 목록 없음, 실행 상세는 바탕 없는 모달', 'O-detail'],
    ['E-7', '통계가 흩어짐 — 머리글 숫자 2개와 도입 화면 한 줄', 'AppHeader · AdoptPage'],
    ['E-8', '벤치마크가 문서형 한 화면 — 문단 4개, 기호 범례 6개, 쪽 높이 2,837px', 'B-summary · B-agent'],
    ['E-9', '공인 벤치마크가 없음 — AgentDojo · InjecAgent · Promptfoo 결과 부재', 'contexa-benchmark/runs'],
    ['E-10', '질문 · 지시형 제목 29개 — 보안 제품이 아니라 퀴즈처럼 읽힘', '11절 제목표'],
    ['E-11', '보안 업무 용어 부재 — "판단" 544, "평소" 291, "체험" 51, "실험실" 31', '문구 사전 5,924키'],
    ['E-12', '색의 뜻이 흔들림 — 빨강 4번 반복, "0건 일치"가 성공색, 금색 454회', '자동 측정 · 눈 검수']])

# ---------------------------------------------------------------- 8 eye notes
s = new_slide('2 · 현행 분석', '눈 검수 요지 (1440 원래 해상도)', '요소 단위로 본 문제 — 시안은 이 목록을 하나씩 없애도록 설계했다')
eyes = [('시작 · 고르기', '화면 70%가 빈 어둠, 카드 오른쪽 절반이 빈칸, 제목 · 설명이 같은 20px · 같은 색, 정렬이 화면마다 다름'),
        ('실시간 판정 2-2', '한 패널에 표현 9가지, 기울어진 "추가 인증" 도장, 두 열 높이 불일치'),
        ('결과 2-3', '1,010px 빨간 막대 4개가 화면을 덮고, 가장 중요한 Contexa 행은 거의 보이지 않는 빈 막대'),
        ('판정 근거 3-3', '한 카드에 글꼴 2 · 언어 2 · 크기 3, 사실 기호(F4 · P1) 설명 없음'),
        ('가능성 비교 5-3', '판정 글자보다 숫자(44px)가 커서 위계가 뒤집힘, 꼬리표 모양 3가지'),
        ('벤치마크', '912px 기둥에 문단이 쌓임, 결론이 문장 속 숫자, 측정 시점 · 표본 한계가 첫 화면에 없음'),
        ('실행 상세', '바탕 없이 960px 모달만, 알약형 탭 7개가 다른 탭과 모양이 다름'),
        ('휴대폰', '6단계 네모 버튼 줄이 맨 위를 차지, 두 줄로 꺾인 알약 버튼(약 100px)이 화면을 덮음')]
for i, (k, d) in enumerate(eyes):
    col, row = i % 2, i // 2; x = 0.6 + col * 6.15; y = 1.6 + row * 1.3
    rect(s, x, y, 5.95, 1.15, 'surface', 'line', radius=0.06)
    text(s, x + 0.25, y + 0.14, 5.5, 0.3, k, 15, 'text', True)
    text(s, x + 0.25, y + 0.47, 5.5, 0.65, d, 14, 't2', spacing=1.08)

# ---------------------------------------------------------------- 9 before/after visuals
PAIRS = [
    ('첫 화면 — 지금(1-1) 대 바뀐 뒤(데모 시작)', '처음 온 방문자가 0번 누르기에 이해하고 1번 누르기에 실행', '1-1', 'd-home',
     '지금: 가운데 제목과 버튼 하나, 화면 70%가 빈 어둠. 무엇을 보여 주는 제품인지 그림이 없음',
     '바뀐 뒤: 실제 판정 기록 한 건(통제 5개 응답 · 반출 · 시간) + 바로 실행 + 위협 시나리오 카드 4'),
    ('1단계 — 지금(C-1 · H-1 두 화면) 대 바뀐 뒤(위협 시나리오 선택)', '공통 요청 하나에서 두 갈래로 — "같은 계정 · 같은 요청"을 그림으로', 'H-1', 'd-pick',
     '지금: 유형(C-1)과 주체(H-1)를 두 화면에서 고름, 카드 3장(304 × 156)에 빈칸이 많음',
     '바뀐 뒤: 묶음 탭 3, 공통 요청 카드 → 탈취된 계정 · 정상 사용자 두 갈래 + 내부자, 정답 꼬리표 · 권장 시작'),
    ('2단계 — 지금(2-1) 대 바뀐 뒤(요청 검토 · 판정 예측)', '요청을 펼쳐 보이고 결정은 하나로', '2-1', 'd-review',
     '지금: 요청 정보는 접는 줄 안, 예측 카드 2장이 전체 폭',
     '바뀐 뒤: 요청 줄 + 사실 5칸(기준선 이탈 표시) + 업무 컨텍스트 + 통제 5 압축 + 예상 판정 + 실행 — 한 화면'),
    ('4단계 — 지금(2-3) 대 바뀐 뒤(결과 · 판정 근거)', '결론 · 비교 그림 · 근거 3 · 다음 확인 3', '2-3', 'd-result',
     '지금: 1,010px 빨간 막대 4개, Contexa 행은 빈 막대, 근거는 접는 줄 안',
     '바뀐 뒤: 결론 카드 + 반출 비교(통제 색) + 판정 시간 · 적용 방식 + 근거 3(사실 ID) + 다음 확인 3'),
    ('비교 — 지금(4-3) 대 바뀐 뒤(같은 요청, 다른 판정)', '이 데모의 핵심 장면', '4-3', 'd-compare',
     '지금: 비교 표 + 칩 7개, 학습 숫자가 한 패널에 섞임',
     '바뀐 뒤: 두 실행 카드 + 요청 사실 대조표(다른 것은 단말 하나) + 통찰 + 기준선 학습'),
]
for t, sub, a_name, b_name, cap_a, cap_b in PAIRS:
    two_images('2 · 지금 대 바뀐 뒤', t, sub, AUD / 'first' / f'{a_name}-ko-1440.png', OUT / f'{b_name}-1440.png', cap_a, cap_b,
               a_crop=(0, 900), b_crop=(0, 900), a_scale=1, b_scale=2)
two_images('2 · 지금 대 바뀐 뒤', '벤치마크 — 지금(B-summary) 대 바뀐 뒤(표준 벤치마크)', '자체 사례만 문서형으로 쌓던 화면을 공인 표준 결과 행렬로',
           AUD / 'first' / 'B-summary-ko-1440.png', OUT / 's-bench-1440.png',
           '지금: 912px 기둥에 소개 문단 4개 + 기준 표 + 기호 범례 6개. 공인 벤치마크 없음, 측정 시점 · 한계가 첫 화면에 없음',
           '바뀐 뒤: 요약 띠(동결 · 무수정 · 모델 · 비용) + 결과 행렬(공식 지표 · 95% 구간 · McNemar · 표본). 한계와 정상 업무 영향은 같은 화면',
           a_crop=(0, 900), b_crop=(0, 900), a_scale=1, b_scale=2)
two_images('2 · 지금 대 바뀐 뒤', '실행 상세 — 지금(바탕 없는 모달) 대 바뀐 뒤(판정 상세 화면)', '주소로 바로 들어오는 독립 화면 + 탭 7',
           AUD / 'first' / 'O-detail-ko-1440.png', OUT / 's-log-detail-1440.png',
           '지금: 960px 모달 안 알약형 탭 7개, 이름-값 모두 20px, 바탕 화면 없음',
           '바뀐 뒤: 요약 띠 + 탭 7, 인용 사실 → 근거 코드 표, 가설 평가(가능성 막대 · 지지 · 반박 사실 칩)',
           a_crop=(0, 900), b_crop=(0, 900), a_scale=1, b_scale=2)

# ---------------------------------------------------------------- 10 reference evaluation
s = new_slide('3 · 설계 원칙', '참고 화면 평가와 넘어설 지점', '참고 화면은 틀을 베끼지 않는다 — 원칙만 가져오고 화면은 Contexa 내용에 맞게 새로 설계')
cols = [('참고 화면의 장점', ['고정 왼쪽 메뉴 · 공통 페이지 머리', '탭 · 필터 막대 · 수치 카드 · 표', '오른쪽 상세, 모달은 상세에만', '틀 · 탐색 · 일관성은 좋은 표준 관리자 템플릿 수준']),
        ('참고 화면의 약점', ['표 머리 · 보조 글이 작고 흐려 대비가 약함', '수치 카드의 절반이 빈칸', '일 단위 값을 곡선으로 이어 없는 값을 그림', '오류 원문을 표 칸에 그대로 쏟음', '"…" 행 동작 · 비활성 버튼의 뜻이 불분명', '범용 템플릿이라 제품 고유의 표현이 없음']),
        ('Contexa가 더하는 것', ['분명한 위계(글자 9단계 · 굵기 4단)', '목적 있는 밀도 — 첫 화면에 결론', '사실대로 그리는 차트(점 · 막대 · 계단선, 구간 수염)', '판정 → 근거 → 원문의 고유한 표현', '실제 데이터 · 표본 · 출처를 숫자 옆에', '한 · 영 · 다크 · 라이트 · 5폭에서 같은 품질'])]
for i, (h, items_) in enumerate(cols):
    x = 0.6 + i * 4.1
    rect(s, x, 1.6, 3.85, 5.15, 'surface', 'line', radius=0.04)
    text(s, x + 0.25, 1.8, 3.4, 0.4, h, 17, 'brand' if i == 2 else 'text', True)
    text(s, x + 0.25, 2.35, 3.45, 4.3, [[('·  ', {'color': 't3'}), (t, {})] for t in items_], 14, 't2', spacing=1.25)

# ---------------------------------------------------------------- 11 principles
paged_table('3 · 설계 원칙', '설계 원칙 11개', None, [0.75, 3.4, 7.95], [
    ['ID', '원칙', '내용'],
    ['P-1', '메뉴의 성격대로', '실행형은 단계 표시, 조회형은 필터 · 표 · 탭, 설명형은 탭 · 카드. 성격이 다른 화면을 이전 · 다음으로 잇지 않는다'],
    ['P-2', '첫 화면에 결론', '맨 위 카드에 그 화면의 답(판정 · 핵심 수치 · 이유 한 줄)'],
    ['P-3', '접기 · 모달은 예외', '판정 · 이유 · 수치 · 표본/한계는 절대 접지 않는다'],
    ['P-4', '같은 정보는 같은 모양', '판정 뱃지 5 · 평가 뱃지 5 · 실행 ID 코드 칩 · 수치 카드 · 시각 형식 고정'],
    ['P-5', '한 화면 한 목적', '탭 하나가 한 질문에 답한다'],
    ['P-6', '실제 데이터만', '포털 응답 · 원자료 값만. 표본 · 기간 · 출처를 숫자 옆에'],
    ['P-7', '세계 수준의 기본기', '한 · 영 같은 배치, WCAG 2.2 AA, 키보드, 다크 · 라이트, 5폭 넘침 0'],
    ['P-8', '사실은 지우지 않는다', '옛 화면의 사실은 모두 새 위치로(Q-84)'],
    ['P-9', '요소 하나까지 규격대로', '토큰 밖 크기 · 간격 · 색은 자동 검사로 막는다'],
    ['P-10', '늘어날 것을 전제로', '메뉴 · 탭 · 벤치마크 · 언어를 더해도 기존 화면을 고치지 않는다'],
    ['P-11', '보안 업무의 말로', '용어 체계와 문체 규칙. 체험 · 게임 · 퀴즈형 표현 금지']])

# ---------------------------------------------------------------- 12 menu
s = new_slide('3 · 정보 구조', '왼쪽 메뉴 — 방문자 동선 순서, 5묶음 13메뉴 + 바닥 2', '데모 시작 → 위협 시뮬레이션 → 결과 분석 → 검증 → 도입 · 운영. 보안 현황 대시보드는 없앰(v3)')
W3 = [1.75, 2.3, 2.0]
table(s, 0.6, 1.55, W3, [['묶음', '메뉴(한)', '메뉴(영)'],
    ['라이브 데모', '데모 시작', 'Start the demo'],
    ['위협 시뮬레이션', '계정 탈취 · 내부자 위협', 'ATO & insider threat'], ['', 'AI 에이전트 위임 남용', 'AI agent delegation abuse'],
    ['', '요청 급증 대응', 'Request surge handling'], ['', '정책 시뮬레이터', 'Policy simulator'],
    ['결과 분석', '판정 이력', 'Decision log'], ['', 'AI 판정 엔진', 'AI decision engine']])
table(s, 6.85, 1.55, W3, [['묶음', '메뉴(한)', '메뉴(영)'],
    ['결과 분석', '탐지 방식 비교', 'Detection comparison'],
    ['검증', '표준 벤치마크', 'Standard benchmarks'], ['', '시나리오 검증', 'Scenario validation'],
    ['도입 · 운영', '도입 · 연동 가이드', 'Deployment & integration'], ['', '운영 지표', 'Operational metrics'], ['', '제품 투어', 'Product tour'],
    ['바닥', '보안 용어집 · 개인정보', 'Glossary · Privacy']])
text(s, 0.6, 5.85, 12.1, 1.0, [[('실행형(집중 모드)  ', {'bold': True, 'color': 'brand'}), ('위협 시뮬레이션 4메뉴 — 메뉴를 아이콘 레일로 접고 안내형 4단계', {})],
                              [('조회형  ', {'bold': True, 'color': 'text'}), ('판정 이력 · 탐지 방식 비교 · 표준 벤치마크 · 시나리오 검증 · 운영 지표 — 필터 · 표 · 탭', {})],
                              [('첫 화면 · 설명형  ', {'bold': True, 'color': 'text'}), ('데모 시작 · AI 판정 엔진 · 도입 · 연동 가이드 · 제품 투어', {})]], 14, 't2', spacing=1.15)

# ---------------------------------------------------------------- 13 old -> new
paged_table('3 · 정보 구조', '옛 메뉴 · 화면 → 새 위치', '사실은 모두 옮긴다(P-8). 고르기 · 다음 단계 화면은 왼쪽 메뉴가 대신한다', [6.0, 6.1], [
    ['옛 이름', '새 위치'],
    ['처음부터 다시 · 시작(1-1)', '라이브 데모 › 데모 시작'],
    ['본 체험: 사람의 요청(2-x · 4-x · 5-x)', '위협 시뮬레이션 › 계정 탈취 · 내부자 위협'],
    ['본 체험: 에이전트의 요청(6-1~6-5 · 6-7)', '위협 시뮬레이션 › AI 에이전트 위임 남용'],
    ['몰림 요청(6-6) · 같은 조회 다섯 번(M-stack)', '위협 시뮬레이션 › 요청 급증 대응'],
    ['실험실(L-x)', '위협 시뮬레이션 › 정책 시뮬레이터'],
    ['판단 과정 · 학습 · 타이밍 · 따라가기(3-x · M-x)', '결과 분석 › AI 판정 엔진'],
    ['규칙과 비교(7-x) · 다섯 방식(M-approaches)', '결과 분석 › 탐지 방식 비교'],
    ['벤치마크(B-x)', '검증 › 시나리오 검증(자체 측정)'],
    ['(없음)', '검증 › 표준 벤치마크(새로, contexa-benchmark 결과)'],
    ['운영 통계(머리글 숫자 · 도입 화면 한 줄)', '도입 · 운영 › 운영 지표(새 메뉴)'],
    ['실행 상세 모달 · 재생 · 오늘 확인한 세 가지(8-1)', '결과 분석 › 판정 이력 › 판정 상세'],
    ['도입하기(O-adopt · 8-2) · 미리보기 영상', '도입 · 운영 › 도입 · 연동 가이드 · 제품 투어'],
    ['유형 · 주체 고르기(C-1 · H-1 · A-1)', '위협 시뮬레이션 1단계 한 화면(묶음 탭 3)'],
    ['다음 단계 고르기(H-6 · A-6 · D-1 · M-more)', '결과 화면의 다음 확인 3개 + 왼쪽 메뉴']])

# ---------------------------------------------------------------- 14 frame diagram
s = new_slide('4 · 화면 틀', '공통 화면 틀', '모든 화면이 같은 틀 — 실행형만 탭 자리에 단계 표시가 온다')
X, Y, WW, HH = 0.6, 1.55, 8.3, 5.25
rect(s, X, Y, WW, HH, 'bg', 'line2')
rect(s, X, Y, 1.55, HH, 'side', 'line'); text(s, X + 0.15, Y + 0.15, 1.3, 2.0, ['왼쪽 메뉴', '248', '', '묶음 제목', '메뉴 36', '지금 위치', '금색 띠'], 14, 't2', spacing=1.1)
rect(s, X + 1.55, Y, WW - 1.55, 0.5, 'bg', 'line'); text(s, X + 1.7, Y + 0.1, 6.5, 0.3, '맨 위 바 56 · 빵가루 · 검색 · 상태 알약 · 언어 · 테마', 14, 't2')
cx = X + 1.8; cw = WW - 2.05
rect(s, cx, Y + 0.7, cw, 0.75, 'bg', 'line2', radius=0.04); text(s, cx + 0.15, Y + 0.78, cw - 0.3, 0.6, ['페이지 머리: 분류 줄 → 제목 28/700 → 설명 15', '오른쪽 동작 ≤ 2(주 동작 금색 1)'], 14, 't2', spacing=1.05)
rect(s, cx, Y + 1.55, cw, 0.42, 'bg', 'line2', radius=0.04); text(s, cx + 0.15, Y + 1.62, cw - 0.3, 0.3, '탭 44 (실행형은 단계 표시)', 14, 't2')
for k in range(4):
    rect(s, cx + k * (cw / 4), Y + 2.1, cw / 4 - 0.1, 0.75, 'surface', 'line', radius=0.06)
text(s, cx + 0.12, Y + 2.3, cw - 0.2, 0.4, '수치 카드 × 4 — 이름 13 · 값 32/700 · 표본 줄', 14, 't2')
rect(s, cx, Y + 3.0, cw * 0.64, 2.05, 'surface', 'line', radius=0.04); text(s, cx + 0.15, Y + 3.15, cw * 0.6, 1.6, ['본문 카드 8열', '표 · 차트', '머리 18/600', '행 48'], 14, 't2', spacing=1.1)
rect(s, cx + cw * 0.66, Y + 3.0, cw * 0.34, 2.05, 'surface', 'line', radius=0.04); text(s, cx + cw * 0.66 + 0.12, Y + 3.15, cw * 0.32, 1.6, ['오른쪽 상세 4열', '이름-값', '동작 2'], 14, 't2', spacing=1.1)
text(s, 9.2, 1.6, 3.6, 5.2, [[('세로 리듬', {'bold': True, 'color': 'text'})], '머리 → 24 → 탭 → 24 → 카드, 카드 사이 16', '',
                             [('본문', {'bold': True, 'color': 'text'})], '안쪽 28 · 32(넓은) / 20 · 16(휴대폰), 최대 폭 1320, 12열 · 간격 16', '',
                             [('카드', {'bold': True, 'color': 'text'})], '모서리 12, 선 1px, 머리 18 · 24, 본문 20 · 24 · 24', '',
                             [('반응형', {'bold': True, 'color': 'text'})], '≥1280 메뉴 펼침 · 1024 아이콘 · ≤1023 서랍'], 14, 't2', spacing=1.12)

# ---------------------------------------------------------------- 15-16 element spec
paged_table('4 · 요소 규격', '요소 규격 (넓은 화면, 4px 격자)', '시안에 그대로 적용한 값 — 토큰 밖 값은 구현 때 자동 검사로 막는다', [2.3, 9.8], [
    ['요소', '규격'],
    ['맨 위 바', '높이 56, 안쪽 32, 검색 260 × 34, 상태 알약 30, 아이콘 버튼 36 × 36'],
    ['왼쪽 메뉴', '너비 248, 묶음 제목 12/600(위 20 · 아래 8), 항목 36 · 안쪽 12 · 아이콘 18 + 10 · 글 14/500, 지금 항목 바탕 + 금색 띠 3px + 600'],
    ['페이지 머리', '분류 줄(뱃지 22 · 코드 24) → 6 → 제목 28/700 → 8 → 설명 15(최대 760), 동작 최대 2 · 주 동작 1'],
    ['탭', '높이 44, 간격 28, 15/500(지금 600 + 금색 밑줄 2px), 개수 알약 12, 휴대폰은 가로 밀기'],
    ['단계 표시', '원 28(지금 금색 · 끝난 단계 체크), 이름 14, 연결선 56, 휴대폰은 지금 단계 이름만'],
    ['카드 · 수치 카드', '모서리 12 · 선 1px · 머리 18/600. 수치 카드: 아이콘 칩 40 · 이름 13 · 값 32/700 + 단위 15 · 표본 줄 13'],
    ['표', '머리 40(13/600) · 행 48 · 칸 안쪽 16, 숫자 오른쪽 정렬 고정폭, 선택 행 파랑, Contexa 행 금색 띠'],
    ['뱃지 · 코드 칩', '판정 · 평가 뱃지 22 · 안쪽 8 · 12/600 · 모서리 6. 코드 칩 고정폭 13 · 높이 24 · 누르면 복사'],
    ['버튼', '기본 36(14/600 · 아이콘 16), 작은 32(13), 큰 44(실행 주 동작 · 휴대폰 아래 고정). 주 · 보조 · 글 · 위험'],
    ['입력 · 막대', '폼 40 · 필터 34, 이름 위 13/500 · 간격 6. 범위 막대 6 · 손잡이 18(파랑)'],
    ['이름-값 · 안내 줄', '이름 132 + 값 14, 줄 간격 10. 안내 줄 아이콘 16 + 글 14, 바탕 surface-2'],
    ['상세 패널 · 모달', '패널 340~400 · 머리 56 · 동작 2. 모달 560 · 720(확인 · 상세에만)'],
    ['차트', '일 단위 값은 점 · 막대 · 계단선, 구간은 수염, 축 12, 수치 표 보기 함께'],
    ['상태', '조작 5상태(기본 · 올림 · 초점 2px · 누름 · 비활성 + 이유), 목록 3상태(빈 · 뼈대 · 오류 + 다시 시도)'],
    ['숫자 · 시각', '천 단위 구분, YYYY-MM-DD HH:mm UTC(현지 시각 툴팁), 지연 p50 · p95']])

# ---------------------------------------------------------------- 17 type
paged_table('4 · 디자인 체계', '글자 체계 — 9단계, 굵기 4단', 'Pretendard · JetBrains Mono, 한국어 word-break: keep-all. 시안 측정 결과 정확히 9종', [1.8, 3.5, 6.8], [
    ['크기', '굵기', '역할'],
    ['32', '700', '수치 카드 값 · 큰 비교 수치'],
    ['28', '700', '페이지 제목(휴대폰 24)'],
    ['24', '700', '결과 카드 결론 한 줄 · 결과 타일 값'],
    ['18', '600', '카드 제목'],
    ['16', '600', '보조 카드 제목 · 단계 이름'],
    ['15', '400 · 500 · 600', '본문 · 탭 · 강조 값'],
    ['14', '400 · 500 · 600', '표 · 이름-값 · 버튼 · 메뉴'],
    ['13', '400 · 500 · 600', '보조 · 표 머리 · 출처 · 표본 · 코드 칩'],
    ['12', '400 · 500 · 600', '뱃지 · 축 · 눈금 · 묶음 제목']])

# ---------------------------------------------------------------- 18 color
s = new_slide('4 · 디자인 체계', '색 — 토큰과 색의 뜻', '다크 기본 + 라이트. 금색은 로고 · 주 동작 · 지금 위치 · Contexa 식별에만, 선택 · 링크 · AI 강조는 파랑')
sw = [('bg', '0A0F1C', 'F5F7FB'), ('surface', '101828', 'FFFFFF'), ('surface-2', '151F33', 'F7F9FC'), ('surface-3', '1A263E', 'EEF2F8'), ('line', '1E2A42', 'E3E8F0'),
      ('text', 'E9EDF5', '0E1626'), ('text-2', 'B3BDD0', '3E4A60'), ('text-3', '8592AB', '5F6B80'), ('brand', 'E6B84F', 'B88415'), ('link', '7FA6FF', '2F5BD8')]
text(s, 0.6, 1.55, 3, 0.3, '다크', 15, 'text', True); text(s, 3.45, 1.55, 3, 0.3, '라이트', 15, 'text', True)
for i, (n, d, l) in enumerate(sw):
    y = 1.95 + i * 0.47
    rect(s, 0.6, y, 0.6, 0.36, d, 'line2', radius=0.15); text(s, 1.32, y + 0.04, 2.0, 0.3, [[(n + ' ', {'bold': True, 'color': 'text'}), ('#' + d, {'mono': True})]], 14, 't2')
    rect(s, 3.45, y, 0.6, 0.36, l, 'line2', radius=0.15); text(s, 4.17, y + 0.04, 1.6, 0.3, '#' + l, 14, 't2', mono=True)
rect(s, 6.3, 1.55, 6.5, 5.25, 'surface', 'line', radius=0.03)
text(s, 6.55, 1.75, 6.0, 5.0, [[('색의 뜻 규칙', {'bold': True, 'color': 'text', 'size': 16})],
                               [('금색  ', {'bold': True, 'color': 'brand'}), ('로고 · 주 동작 · 지금 위치(메뉴 · 탭 · 단계 · 쪽) · 통제 비교의 Contexa', {})],
                               [('파랑  ', {'bold': True, 'color': 'link'}), ('링크 · 선택(행 · 스위치 · 범위 막대 · 조건 · 선택 카드) · AI 단계 · 사실 ID', {})],
                               [('판정 5색  ', {'bold': True, 'color': 'text'}), ('판정 · 평가 뱃지와 판정 분포에만', {})],
                               [('빨강  ', {'bold': True, 'color': 'block'}), ('차단 · 미탐 · 오탐에만. "0건"이나 "일치"에 초록을 쓰지 않는다', {})],
                               [('중립  ', {'bold': True, 'color': 'text'}), ('안내 상자 · 분류 뱃지 · 하위 탭 선택은 중립색', {})], '',
                               [('대비(계산값, 카드 바탕 기준)', {'bold': True, 'color': 'text', 'size': 16})],
                               '다크: 글 15.1 · 9.4 · 5.7, 파랑 7.4, 주 버튼 글 10.0, 판정 뱃지 4.5~6.7',
                               '라이트: 글 18.1 · 8.9 · 5.4, 파랑 5.8, 주 버튼 글 5.6, 판정 뱃지 4.6~5.1',
                               [('계산 중 기준 미달 4곳(라이트 주 버튼 흰 글 3.3 · 허용 4.0 · 추가 인증 3.7, 다크 판정 없음 4.2)을 찾아 토큰을 고쳤다', {'color': 't3'})]],
     14, 't2', spacing=1.2)

# ---------------------------------------------------------------- 19 badges
s = new_slide('4 · 디자인 체계', '판정 뱃지 · 평가 뱃지 · 통제 색', '같은 정보는 어디서나 같은 모양(P-4). 아이콘 + 글로 구분하고 색만으로 구분하지 않는다')
text(s, 0.6, 1.55, 6, 0.35, '판정 뱃지 5종 (Contexa의 처분)', 16, 'text', True)
bd = [('허용', 'Allow', 'allow', '✓'), ('추가 인증', 'Step-up', 'stepup', '⚿'), ('검토 보류', 'Hold for review', 'hold', '⏸'), ('차단', 'Block', 'block', '⊘'), ('판정 없음', 'No decision', 'none', '–')]
for i, (k, e, c, ic) in enumerate(bd):
    x = 0.6 + i * 2.45
    sh = rect(s, x, 2.0, 2.2, 0.5, C[c], None, radius=0.2); sh.fill.fore_color.rgb = rgb(C[c])
    label_shape(sh, f'{ic} {k}', 15, 'bg', True)
    text(s, x, 2.6, 2.2, 0.3, e, 14, 't2', align=PP_ALIGN.CENTER)
text(s, 0.6, 3.15, 12, 0.35, '평가 뱃지 5종 (정답 대비 결과, 아이콘 없음)', 16, 'text', True)
ev = [('적중', 'allow'), ('정상 처리', 'allow'), ('일부 반출 뒤 차단', 'stepup'), ('미탐', 'block'), ('오탐', 'block')]
for i, (k, c) in enumerate(ev):
    x = 0.6 + i * 2.45
    sh = rect(s, x, 3.6, 2.2, 0.5, 'surface', C[c], radius=0.2); label_shape(sh, k, 15, C[c], True)
text(s, 0.6, 4.45, 12, 0.35, '통제 5색 (통제 비교 막대 · 범례)', 16, 'text', True)
ctl = [('웹 방화벽(WAF)', '4F5D78'), ('인증 · 권한(IAM)', '5E6E8C'), ('임계값 규칙', '7181A0'), ('승인 정책 규칙', '8A98B5'), ('Contexa', 'E6B84F')]
for i, (k, c) in enumerate(ctl):
    x = 0.6 + i * 2.45
    rect(s, x, 4.9, 2.2, 0.28, c, None, radius=0.5); text(s, x, 5.28, 2.2, 0.3, k, 14, 'text' if k == 'Contexa' else 't2', k == 'Contexa', align=PP_ALIGN.CENTER)
text(s, 0.6, 5.95, 12.2, 0.8, '실제 화면의 뱃지는 바탕 14~16% + 글 100%(높이 22, 12/600). 이 장의 뱃지는 읽기 쉽게 크게 그렸다. 기존 통제 4개는 회청 단계, Contexa만 금색 — "누가 Contexa인가"가 색으로 바로 보인다.', 14, 't2', spacing=1.12)

# ---------------------------------------------------------------- v3 flow
paged_table('5 · 체험 흐름 (v3)', '왜 다시 설계했나 — 체험 흐름의 원칙 9개', 'v2는 처음 온 방문자에게 관리 콘솔로 보였다. 현행의 장점(버튼 하나 · 한 화면 한 결정 · 같은 계정 이야기)은 살리고 약점은 없앤다', [0.8, 2.9, 8.4], [
    ['ID', '원칙', '화면에서'],
    ['F-1', '0번 누르기에 이해', '첫 화면에서 실제 판정 기록 한 건: 같은 요청에 기존 통제 4개는 허용(480건 × 4), Contexa는 추가 인증(0건)'],
    ['F-2', '1번 누르기에 실행', '주 동작 "계정 탈취 시나리오 실행"은 1단계를 건너뛰고 2단계로 바로'],
    ['F-3', '한 화면 한 결정', '1단계 시나리오 고르기 · 2단계 예상 판정 · 3단계 지켜봄 · 4단계 다음 확인 고르기'],
    ['F-4', '집중 모드', '체험 중 메뉴를 72px 아이콘 레일로 접고, 본문을 1120px 가운데로'],
    ['F-5', '기다림을 이해로', '판정 6~16초 동안 Contexa가 확인하는 단계를 실제 기록으로 채움'],
    ['F-6', '결과의 네 요소', '결론 한 문장 · 반출 비교 그림 · 근거 3가지(사실 ID) · 다음 확인 3개'],
    ['F-7', '대조군이 핵심 장면', '1순위 다음 확인 = 같은 요청을 정상 사용자로 → "같은 요청, 다른 판정"'],
    ['F-8', '정답은 정직하게', '위협 · 정상 업무 · 정답 미지정을 보이고, 통제에는 전달되지 않음을 밝힘'],
    ['F-9', '진행 표시는 업무의 말로', '"이 묶음에서 실행한 시나리오 n / 3" — 점수 · 배지 · 게임 표현 없음']])
paged_table('5 · 체험 흐름 (v3)', '현행 대 새 설계 — 단계별', None, [1.7, 4.9, 5.5], [
    ['단계', '현행', '새 설계'],
    ['첫 화면', '1-1: 가운데 제목과 버튼 하나, 화면 70%가 빈칸', 'd-home: 실제 판정 기록 카드 + 바로 실행 + 시나리오 카드 4 + 진행 방식 + 표준 벤치마크 띠'],
    ['유형 · 주체', 'C-1 → H-1 두 화면, 카드 절반이 빈칸', 'd-pick: 묶음 탭 3, 공통 요청에서 두 갈래 + 내부자, 정답 꼬리표'],
    ['요청 · 예측', '2-1: 요청 정보가 접혀 있고 예측 카드만', 'd-review: 요청 줄 + 사실 5칸 + 컨텍스트 + 통제 5 + 예상 판정 + 실행, 한 화면'],
    ['실시간', '2-2: 한 패널 표현 9가지, 빨간 막대 반복', 'd-live: 통제 5행 + Contexa 판정 진행(실제 단계) + 대비 요약'],
    ['결과', '2-3: 빨간 막대 4개, 근거는 접는 줄', 'd-result: 결론 + 반출 비교 + 판정 시간 · 적용 방식 + 근거 3 + 다음 확인 3'],
    ['비교', '4-3: 비교 표 + 칩 7개', 'd-compare: 두 실행 카드 + 사실 대조표(단말 하나) + 통찰 + 학습']])
FLOW = [
 ('5 · 체험 흐름 (v3)', '데모 시작', '첫 화면 · 데이터: 공개 녹화 실행 run-04cdd89264f7, 표준 벤치마크 결과 묶음', 'd-home.html', [
   ('.hero-title', '히어로 제목', '32/700, 핵심 이야기 한 문장'),
   ('.hero-cta', '바로 실행', '주 동작 44 — 1단계를 건너뜀'),
   ('.hero .card', '공개 녹화 실행', '통제 5행 · 반출 · 응답 시간'),
   ('.scen.rec', '위협 시나리오 카드', '정답 꼬리표 · 확인하는 것 · 요청 수'),
   ('.how', '진행 방식', '4단계를 미리 안내'),
   ('.trust', '표준 벤치마크 띠', '공식 지표 · 보호 없음 → 적용')]),
 ('5 · 체험 흐름 (v3)', '1단계 — 위협 시나리오 선택(사람)', '집중 모드 · 카드를 누르면 바로 2단계', 'd-pick.html', [
   ('.stepper', '단계 표시', '메뉴는 아이콘 레일로 접힘'),
   ('.seg-tabs', '묶음 탭', '사람 3 · 에이전트 5 · 급증 1'),
   ('.shared', '공통 요청', '같은 계정 · 시각 · 네트워크 · 로그인 · 요청'),
   ('.fork', '두 갈래', '같은 요청이 두 주체로 나뉨'),
   ('.subj.rec', '탈취된 계정', '권장 시작, 다른 점은 처음 확인 단말'),
   ('.insider', '내부자 권한 남용', '요청 3건, 확인하는 것')]),
 ('5 · 체험 흐름 (v3)', '1단계 — 위협 시나리오 선택(AI 에이전트)', '정답: T5 · M22A · M10A 위협, N1 정상, M14A 정답 미지정', 'd-pick-agent.html', [
   ('.chainc', '위임 사슬', '위임자 → 에이전트 → 대상'),
   ('.valid', '모두 유효', '토큰 · 권한 · 사람의 위임'),
   ('.ac.rec', 'T5 권장 시작', '위임 만료 뒤의 예약 실행'),
   ('.ac .instr', '지시 원문', '위임자가 준 지시 그대로')]),
 ('5 · 체험 흐름 (v3)', '2단계 — 요청 검토 · 판정 예측', '결정은 예상 판정 하나 · 1440 × 900 한 화면', 'd-review.html', [
   ('.ph-kicker', '분류 · 정답', '정답은 통제에 전달되지 않음'),
   ('.kf', '핵심 사실 5칸', '값 16/600, 기준선 이탈 뱃지'),
   ('.ctx', '업무 컨텍스트', '담당 · 예외 · 승인 · 티켓 · 당번'),
   ('.ctls', '통제 5 압축', '각 통제가 보는 것 한 줄'),
   ('.preds', '예상 판정', '선택 카드 2, 선택은 파랑'),
   ('.run-bar', '실행 막대', 'p50 · p95 · 하루 10회 + 요청 실행')]),
 ('5 · 체험 흐름 (v3)', '3단계 — 실시간 판정', '진행 중 화면 예시(6.2초 시점) · 단계 내용은 실제 기록', 'd-live.html', [
   ('.live-pill', '상태 알약', '판정 중 · 경과 시간'),
   ('.row5.cx', 'Contexa 행', '판정 중 · 반출 대기'),
   ('.flow', '판정 진행', '실제 단계 기록, 시각이 없는 단계는 비움'),
   ('.fl.now', 'AI 추론', '모델 · 토큰 · 진행 막대(파랑)'),
   ('.sum', '대비 요약', '0.041초 허용 대 판정 전 보류')]),
 ('5 · 체험 흐름 (v3)', '4단계 — 결과 · 판정 근거', '결론 · 비교 · 근거 · 다음 확인', 'd-result.html', [
   ('.verdict', '결론 카드', '24/700 한 문장'),
   ('.v-side', '예상 판정 · 시간', '적중 · 10.2초 · 실행 ID'),
   ('.cmp-row', '반출 비교', '통제 색 막대 + 평가 뱃지'),
   ('.lat', '판정 시간 · 적용', '동기 보류, 비동기 안내'),
   ('.why', '판정 근거 3', '사실 ID + AI 요약(번역)'),
   ('.nx.primary', '다음 확인 1순위', '같은 요청을 정상 사용자로')]),
 ('5 · 체험 흐름 (v3)', '같은 요청, 다른 판정', '4단계의 탭 · 이 데모의 핵심 장면', 'd-compare.html', [
   ('.tabs', '4단계 안의 탭', 'S13 · S13T · 비교'),
   ('.runc', '두 실행 카드', '판정 · 반출 · 위험도 · 평가'),
   ('table.dt', '요청 사실 대조표', '같음 · 다름 7행'),
   ('tr.diff', '다른 것은 단말', '그 행만 파랑'),
   ('.ins', '통찰', '규칙은 두 요청을 구분 못함'),
   ('.learn', '기준선 학습', '48 → 48 대 48 → 49')]),
]
for k, t, sub, f, notes in FLOW:
    screen_slide(k, t, sub, f, notes)

# ---------------------------------------------------------------- screens
SCREENS = [
 ('6 · 화면별 설계 · 결과 분석', '판정 이력', '조회형 · 필터 · 표 · 오른쪽 상세 · 데이터: 방문자 실행 목록, /api/runs/{id}/score', 's-log.html', [
   ('.filters', '필터 막대', '기간 · 위협/정상 · 판정 · 결과 · 검색(높이 34)'),
   ('table.table thead', '표 머리', '40 · 13/600, 숫자 열 오른쪽 정렬'),
   ('tr.is-sel', '선택 행', '파랑 바탕 + 왼쪽 띠 3px(선택은 파랑)'),
   ('.panel', '오른쪽 상세 340', '요청 · Contexa 판정 · 5개 통제별 반출, 동작 2'),
   ('.pager', '쪽 넘김', '32 단추, 지금 쪽만 금색(지금 위치)')]),
 ('6 · 화면별 설계 · 결과 분석', '판정 상세 — 판정 근거 탭', '조회형 · 탭 7 · 데이터: /api/runs/{id}/steps/{n}/facts · anatomy · quality · result', 's-log-detail.html', [
   ('.ph-kicker', '분류 줄', '위협 유형(중립 뱃지) · 시나리오 코드 · 평가 뱃지'),
   ('.sumbar', '요약 띠', '요청 · 주체 · 위험도 · 시간 · 시각'),
   ('.tabs', '탭 7', '원문 · 검증 · 학습을 탭으로 나눠 접기 0'),
   ('table.ft', '인용 사실 표', '사실 ID · 원문 2줄 · 근거 · 근거 코드'),
   ('.summary', 'AI 판정 요약', '모델 문장의 번역, "번역" 꼬리표'),
   ('.hyp', '가설 평가', '가능성 3칸 막대 + 지지 · 반박 사실 칩')]),
 ('6 · 화면별 설계 · 도입 · 운영', '운영 지표', '조회형 · 탭 5 · 데이터: /api/stats만(새 값은 따로 승인)', 's-metrics.html', [
   ('.kpi', '수치 카드 4', '판정 · p50 · 완료 실행 · 방문자 실행'),
   ('.dist', '판정 분포', '판정 5색 막대 + 표'),
   ('.lat', '판정 시간', 'p50 · p95 표시, 0~20초 축'),
   ('section.span-6 table.table', '판정 수 밖 요청', '직전 판정 재사용 · 기술적 실패 · 응답 전 보류'),
   ('.kv', '운영 설정', '엔진 모드 · 실행 사양 · 반복 판정 일치')]),
 ('6 · 화면별 설계 · 위협 시뮬레이션', 'AI 에이전트 위임 남용 — 2단계', '실행형 · 데이터: 위임 시나리오, 에이전트 실행', 's-agent.html', [
   ('.chain', '위임 사슬', '위임자 → AI 에이전트 → 대상 리소스'),
   ('.deleg', '위임 목적 · 범위', '범위 칩, 기간 종료 뱃지'),
   ('.timeline', '위임 기간', '위임 시작 · 종료 · 요청 시각'),
   ('.instr', '지시 원문', '위임자가 에이전트에게 준 지시'),
   ('.opts', '예상 판정', '처리 / 중단 · 위임자 확인')]),
 ('6 · 화면별 설계 · 위협 시뮬레이션', '정책 시뮬레이터 — 임계값 조정', '조회형 탭 · 데이터: /api/rules/cases, /api/rules/evaluate(서버 규칙 클래스 그대로)', 's-policy.html', [
   ('.form', '통제 · 조정 항목', '선택 40'),
   ('.range', '범위 막대 + 값 상자', '선택 요소는 파랑, 기본값 500'),
   ('table.res', '결과 표', '통제 색 막대(기존 회청 · Contexa 금색)'),
   ('table.sweep', '상한값별 결과', '실측 8개 값, 지금 값 열 파랑'),
   ('.insight', '통찰 한 줄', '상한을 낮추면 정상 업무 차단이 더 늘어남')]),
 ('6 · 화면별 설계 · 결과 분석', 'AI 판정 엔진 — 판정 흐름', '설명형 · 탭 5 · 데이터: 기준 실행 anatomy · learning', 's-engine.html', [
   ('.stage', '판정 흐름 7단계', '이번 실행 값(굵게) + 원문 키(고정폭)'),
   ('.stage.ai', 'AI 단계', '파랑 강조 — 모델 · 호출 · 토큰 · 시간'),
   ('.lr-row', '기준선 학습 반영', '48 → 48 학습 안 함 / 비교 24 → 29'),
   ('dl.kv', '무결성 봉인', '봉인 값 · 검사 결과 · 이 데모 설정임을 밝힘')]),
 ('6 · 화면별 설계 · 결과 분석', '탐지 방식 비교 — 임계값 규칙 적용', '조회형 · 탭 3 · 데이터: ThresholdRules, 두 실행 결과', 's-compare.html', [
   ('.rule', '규칙 상태 줄', '스위치(파랑) · 규칙 조건 3가지'),
   ('table.vs', '두 요청 비교', '같은 시각 · 건수, 판정 뱃지'),
   ('.insight', '통찰', '규칙은 두 요청을 구분하지 못함'),
   ('.cond.on', '조건 하나 바꾸기', '이 탭의 유일한 실행 동작')]),
 ('6 · 화면별 설계 · 검증', '표준 벤치마크 — 개요', '조회형 · 데이터: contexa-benchmark 결과 묶음(보고 파일 해시 대조)', 's-bench.html', [
   ('.facts-strip', '요약 띠 5칸', '동결 · 무수정 · 피해 모델 · 판정 모델 · 비용'),
   ('table.mx', '결과 행렬', '공식 지표명, 95% 구간, McNemar, 표본'),
   ('.grp', '벤치마크 묶음 행', 'AgentDojo · InjecAgent · Promptfoo'),
   ('section.span-8 table.table', '정상 업무 영향', '공격 결과와 같은 화면, 자체 지표 뱃지'),
   ('.warn', '한계', '같은 화면, 접지 않음')]),
 ('6 · 화면별 설계 · 검증', '표준 벤치마크 — AgentDojo', '벤치마크별 같은 틀 · 탭: 결과 · 환경별 분해 · 소유자 변형 · 사례 · 설정 · 한계', 's-bench-agentdojo.html', [
   ('.ph-kicker', '상태 · 버전 · 동결', '완료 · agentdojo 0.1.35 · test-v1 해시'),
   ('.ci-chart', '구간 막대 차트', '점추정 + 95% 수염, 보호 없음 · 변형 · 재측정'),
   ('.axis', '축', '0~15%, 격자선 흐림'),
   ('table.env', '환경별 분해', 'banking · slack · travel · workspace')]),
 ('6 · 화면별 설계 · 검증', '시나리오 검증 — 요약', '조회형 · 탭 7 · 자체 측정임을 맨 위에 밝힘', 's-scenario.html', [
   ('.nature', '성격 안내', '자체 측정 — 외부 표준 결과가 아님, 중립색'),
   ('.kpi', '수치 카드 3', '위협 23 · 정상 업무 19 · 정답 미지정 2'),
   ('table.res', '통제별 결과', '결과별 누적 막대 + 미탐 · 오탐 수'),
   ('.note', '해석 안내', '일부 반출 뒤 차단 · 승인 정책 규칙의 한계')]),
 ('6 · 화면별 설계 · 도입 · 운영', '도입 · 연동 가이드', '설명형 · 탭 4 · 데이터: 코어 좌표 · 어노테이션 · 설정 기본값', 's-deploy.html', [
   ('.stp', '연동 절차 3단계', '번호 원(중립) · 제목 16 · 설명 14'),
   ('pre.code-block', '코드 블록', '처음부터 보임, 복사 단추'),
   ('dl.kv', '관찰 모드 · 보관 기본값', '오른쪽 정렬 값, 스타터 0.1.0 기본'),
   ('.links', '문서 링크', '빠른 시작 · 저장소 · 연동 예제')]),
]
for k, t, sub, f, notes in SCREENS:
    if f == 's-bench.html':
        screen_slide(k, t + ' (1/2)', sub, f, notes[:3], 0, 960)
        screen_slide(k, t + ' (2/2)', sub, f, [(a, b, c) for a, b, c in notes[3:]], 920, None)
    else:
        screen_slide(k, t, sub, f, notes)

# ---------------------------------------------------------------- phone
s = new_slide('7 · 휴대폰 · 라이트 · 영어', '휴대폰 390 — 첫 화면', '첫 화면에 결론과 주 동작. 넘침 0(17화면 자동 검사)')
ph = [('d-home', '데모 시작 — 히어로 · 바로 실행'), ('d-pick', '1단계 — 공통 요청 · 갈래'), ('d-review', '2단계 — 아래 고정 요청 실행'), ('d-result', '4단계 — 결론 · 비교'), ('d-compare', '같은 요청, 다른 판정')]
for i, (n, cap) in enumerate(ph):
    p, (pw, phh) = crop(OUT / f'{n}-390-view.png', 0, None, out=f'{n}-phone.png', width=780)
    ih = 4.75; iw = ih * pw / phh; x = 0.6 + i * 2.5
    rect(s, x - 0.03, 1.55 - 0.03, iw + 0.06, ih + 0.06, None, 'line2')
    s.shapes.add_picture(str(p), Inches(x), Inches(1.55), Inches(iw), Inches(ih))
    text(s, x, 1.55 + ih + 0.12, 2.35, 0.6, cap, 14, 't2', spacing=1.05)
s = new_slide('7 · 휴대폰 · 라이트 · 영어', '휴대폰 규칙', '시안에서 검증한 규칙 — 구현 때 부품 시험으로 고정')
for i, (n, cap) in enumerate([('s-log', '판정 이력 — 행 카드'), ('d-pick-agent', '에이전트 1단계 — 사슬 세로')]):
    p, (pw, phh) = crop(OUT / f'{n}-390-view.png', 0, None, out=f'{n}-phone.png', width=780)
    ih = 4.75; iw = ih * pw / phh; x = 0.6 + i * 2.5
    rect(s, x - 0.03, 1.55 - 0.03, iw + 0.06, ih + 0.06, None, 'line2')
    s.shapes.add_picture(str(p), Inches(x), Inches(1.55), Inches(iw), Inches(ih))
    text(s, x, 1.55 + ih + 0.12, 2.35, 0.6, cap, 14, 't2', spacing=1.05)
table(s, 5.75, 1.55, [2.3, 4.75], [
    ['요소', '휴대폰 규칙'],
    ['맨 위 바', '메뉴 · 로고 · 언어만. 메뉴는 왼쪽 서랍'],
    ['페이지 머리', '제목 24, 동작은 가득 찬 너비'],
    ['수치 카드', '2 × 2, 아이콘 빼고 값 24'],
    ['넓은 수치 표', '카드 안 가로 밀기 + 첫 열 고정'],
    ['목록형 표', '행 카드로 쌓기(판정 이력 · 인용 사실)'],
    ['탭 · 단계', '탭은 가로 밀기, 단계는 지금 이름만'],
    ['주 동작', '아래 고정 44, 화면 위 내용을 가리지 않게 여백'],
    ['2단 배치', '1열로 쌓기(주 → 보조 → 나머지)']])

# ---------------------------------------------------------------- light / english
two_images('7 · 휴대폰 · 라이트 · 영어', '라이트 테마', '같은 토큰 이름에 라이트 값 — 대비 기준을 계산으로 맞춤',
           OUT / 'd-home-1440-light.png', OUT / 'd-review-1440-light.png', '데모 시작(라이트)', '2단계 요청 검토 · 판정 예측(라이트) — 선택 카드 파랑')
two_images('7 · 휴대폰 · 라이트 · 영어', '영어판', '같은 배치. 영어 길이 때문에 생긴 줄바꿈 · 겹침 · 넘침을 시안에서 찾아 고쳤다',
           OUT / 'd-home-en-1440.png', OUT / 's-bench-en-1440.png', 'Start the demo — 영어 제목은 두 줄에 맞게 줄임', 'Standard benchmarks — 공식 지표 이름 그대로')

# ---------------------------------------------------------------- benchmark rules
paged_table('8 · 표준 벤치마크', '표준 벤치마크와 시나리오 검증 — 성격이 다르다', '섞으면 둘 다 믿을 수 없게 된다. 두 메뉴로 나눈다', [2.4, 4.85, 4.85], [
    ['', '표준 벤치마크', '시나리오 검증'],
    ['무엇', '공개 벤치마크를 공식 하니스 · 공식 채점 그대로(contexa-benchmark)', '데모 설계 시나리오의 반복 실행 기록'],
    ['시나리오를 만든 사람', '벤치마크 저자(외부)', 'Contexa 팀(표본 내)'],
    ['지표', 'Targeted ASR · Benign Utility · Utility under Attack · ASR-valid · Pass rate', '미탐 · 오탐(데모 채점)'],
    ['믿음의 근거', '실행 전 동결 4판 · 하니스 무수정 검증 · 95% 구간 · McNemar · 비용 장부', '실제 실행 기록과 무결성 봉인'],
    ['화면의 역할', '외부 기준으로 효과를 입증', '데모 시나리오가 보여 주는 것을 설명'],
    ['표현 규칙', '공식 지표 이름만, "인증" 금지(PC-9), 1% 미만은 점추정 + 95% 상한, 불리한 결과 · 한계를 같은 화면에', '첫 카드에 "자체 측정 — 외부 표준 결과가 아님", 측정 시점 · 번들 · 표본'],
    ['데이터 길', '보고 파일 → 결과 묶음 JSON(해시 대조) → 포털 정적 자원. 화면은 다시 세지 않음', '포털 기록']])

# ---------------------------------------------------------------- glossary
GLOSS = [
 ['지금 말(횟수)', '한', '영', '정의'],
 ['판단(544)', '판정', 'Decision', 'Contexa가 요청에 내린 처분'],
 ['통과 · 지나감', '허용', 'Allow', '요청을 그대로 처리'],
 ['추가 확인(3)', '추가 인증', 'Step-up authentication', '추가 인증을 통과해야 요청이 이어짐'],
 ['보류', '검토 보류', 'Hold for review', '응답 전에 멈추고 검토로(HTTP 423)'],
 ['막힘(7)', '차단', 'Block', '요청을 거부'],
 ['판단 없음', '판정 없음', 'No decision', '분석 미완료 · 기술적 실패'],
 ['놓침 · 놓친(34)', '미탐', 'Missed (false negative)', '위협을 허용함'],
 ['잘못 막음(3)', '오탐', 'False positive', '정상 업무를 차단함'],
 ['맞음', '적중', 'Correct', '정답과 같은 처리'],
 ['다섯 보안(34) · 다섯 방식(27)', '5개 보안 통제', 'Five security controls', '같은 요청을 동시에 받는 비교 대상'],
 ['기존 보안(39)', '기존 보안 통제(줄임: 기존 통제)', 'Existing controls', '웹 방화벽 · 인증 · 권한 · 임계값 · 승인 정책'],
 ['방화벽', '웹 방화벽(WAF)', 'Web application firewall', 'OWASP CRS 기반 요청 검사'],
 ['로그인 인증 · 권한', '인증 · 권한(IAM)', 'Identity & access (IAM)', '계정 인증 · 역할 기반 권한'],
 ['고정 규칙', '임계값 규칙', 'Threshold rules', '시각 · 건수 · 휴면 기준'],
 ['승인 규칙', '승인 정책 규칙', 'Approval policy rules', '승인 · 티켓 · 담당 기준'],
 ['평소 · 평소 패턴(291)', '행위 기준선', 'Behavioral baseline', '주체의 학습된 정상 행위 범위'],
 ['평소와 다름', '기준선 이탈', 'Baseline deviation', '기준선 밖의 값'],
 ['회사 기록(50)', '업무 컨텍스트', 'Business context', '배정 · 승인 · 티켓 · 당번 · 출장'],
 ['기기(77)', '단말', 'Device', '요청을 보낸 브라우저 · OS'],
 ['접속 환경 · 장소', '네트워크', 'Network', 'IP 대역 · 영역'],
 ['자료(163) · 나간 자료(23)', '반출 · 반출 건수', 'Export · exported items', '요청으로 나간 문서 수'],
 ['유출', '데이터 유출', 'Data exfiltration', '업무 밖 목적의 반출'],
 ['공격자(35)', '탈취된 계정 · 위협 행위자', 'Compromised account · threat actor', '시나리오 정답(통제에 전달 안 됨)'],
 ['주인의 악용', '내부자 권한 남용', 'Insider privilege misuse', '권한 안의 업무 외 목적 행위'],
 ['위임한 사람(26)', '위임자', 'Delegator', '에이전트에게 업무를 맡긴 사람'],
 ['맡긴 일 · 위임 기록', '위임 범위 · 위임 기간', 'Delegated scope · period', '대상 · 동작 · 기간'],
 ['몰림(2) · 한꺼번에', '요청 급증', 'Request surge', '같은 요청의 동시 유입'],
 ['체험(51)', '위협 시뮬레이션 · 실행', 'Threat simulation · run', '실제 판정으로 시나리오 실행'],
 ['실험실(31)', '정책 시뮬레이터', 'Policy simulator', '임계값 · 조건을 바꿔 다시 판정'],
 ['사례(170)', '시나리오', 'Scenario', '정답이 정해진 요청 묶음'],
 ['내 예측 · 예상', '예상 판정', 'Expected decision', '실행 전에 기록하는 판정 예측'],
 ['처음부터 다시 · 시작', '데모 시작', 'Start the demo', '첫 화면 — 실제 판정 기록과 바로 실행'],
 ['다음 단계 고르기', '다음 확인', 'Next', '결과 화면의 추천 3개'],
 ['(없음)', '대조군', 'Control run', '같은 요청을 정상 주체가 보낸 시나리오'],
 ['(없음)', '정답 미지정', 'Undetermined ground truth', '판정이 갈리는 시나리오, 점수에서 제외'],
 ['(없음)', '집중 모드', 'Focus mode', '체험 중 메뉴를 아이콘 레일로 접는 틀'],
 ['실행 기록(18)', '판정 이력', 'Decision log', '실행 목록과 판정 상세'],
 ['판단 엔진 · 판단 과정', 'AI 판정 엔진 · 판정 흐름', 'AI decision engine · decision flow', '7단계 판정 과정'],
 ['규칙과 비교', '탐지 방식 비교', 'Detection comparison', '규칙 기반 대 문맥 기반'],
 ['벤치마크(외부)', '표준 벤치마크', 'Standard benchmarks', '공식 하니스 · 채점 그대로'],
 ['벤치마크(자체)', '시나리오 검증', 'Scenario validation', '데모 시나리오 반복 측정'],
 ['운영 통계', '운영 지표', 'Operational metrics', '판정 수 · 시간 · 실행 · 일치'],
 ['도입하기(7)', '도입 · 연동 가이드', 'Deployment & integration', '의존성 · 어노테이션 · 모드 · 보관'],
 ['미리보기 영상(3)', '제품 투어', 'Product tour', '메뉴별 안내 영상'],
 ['용어 사전(4)', '보안 용어집', 'Security glossary', '용어 정의'],
 ['위험 점수 · 확신', '위험도 · 확신도', 'Risk score · confidence', '모델이 낸 0~1 값'],
 ['가능성 비교', '가설 평가', 'Hypothesis assessment', '설명을 지지 · 반박 사실로 비교'],
 ['AI가 쓴 이유', 'AI 판정 요약', 'Decision summary', '모델의 한 문장(번역 표시)'],
 ['사실 · 근거 코드', '인용 사실 · 근거 코드', 'Cited fact · reason code', '프롬프트 사실 줄 · 정해진 코드'],
 ['봉인', '무결성 봉인 · 무결성 검증', 'Integrity seal · verification', '해시 봉인과 재계산 검사'],
 ['배운 것 · 학습', '기준선 학습', 'Baseline learning', '허용된 요청만 기준선에 반영'],
 ['관찰만 · 적용', '관찰 모드 · 적용 모드', 'Shadow mode · enforce mode', '기록만 · 적용'],
 ['응답 전 · 다음 요청부터', '동기 판정 · 비동기 판정', 'Synchronous · asynchronous decision', '적용 시점'],
 ['재사용', '직전 판정 재사용', 'Reused prior decision', '유효한 이전 판정으로 처리'],
 ['녹화 기록 · 재생', '공개 녹화 실행', 'Published recorded run', '공개용으로 저장한 실제 실행'],
 ['반복 일치', '반복 판정 일치', 'Decision consistency', '같은 입력의 판정 일치'],
 ['판단 시간', '판정 시간(p50 · p95)', 'Decision latency', '요청 수신부터 판정 기록까지'],
]
paged_table('8 · 용어 · 문체', '보안 업무 용어 체계', '화면의 모든 이름은 이 표의 정식 한 · 영만 쓴다. 괄호 수 = 지금 한국어 사전에서 그 말이 나오는 횟수', [2.85, 2.95, 3.1, 3.2], GLOSS)

paged_table('8 · 용어 · 문체', '문체 규칙', '제목은 명사구, 설명은 단언형. 체험 · 게임 · 퀴즈형 표현을 쓰지 않는다', [0.8, 4.9, 6.4], [
    ['ID', '규칙', '지금 → 바뀐 뒤'],
    ['W-1', '제목은 명사구 — 질문 · 권유 · 명령 금지', '"기존 보안이 모두 놓친 공격, Contexa는 막았을까요?" → "시나리오 검증 요약"'],
    ['W-2', '설명은 1~2문장 단언형, 하는 일 + 데이터 범위(120자 이내)', '"어떤 상황으로 해 볼까요?" → "규칙 기반 통제의 임계값을 바꿔 실제 실행 기록을 다시 판정합니다."'],
    ['W-3', '버튼은 "대상 + 동작" 명사형, 주 동작은 하나', '"체험 시작하기" → "위협 시뮬레이션 시작", "보내기" → "요청 실행"'],
    ['W-4', '체험 · 게임 · 퀴즈 어휘 금지', '"먼저 예상을 고르세요" → "예상 판정 선택"'],
    ['W-5', '판정 · 평가 · 통제는 정식 이름만', '"추가 확인" → "추가 인증"'],
    ['W-6', '숫자 옆에 표본 · 기간 · 출처', '"1.36%" → "1.36% · 664건 · 95% 구간 0.62~2.56%"'],
    ['W-7', '결과 문장은 사실만, 감탄 · 과장 금지', '"놀랍게도 모두 막았습니다!" 금지'],
    ['W-8', '표준 벤치마크는 PC-9', '"인증받은" 금지, 공식 지표 이름'],
    ['W-9', '영어는 Sentence case, 업계 표준어', '"Five Approaches" → "Five security controls"'],
    ['W-10', '모델 원문은 번역하지 않고 원문 표시, 번역엔 꼬리표', '"AI 판정 요약 · 번역"']])

TITLES = [
 ['번호', '지금 제목', '새 위치', '새 제목(한 / 영)'],
 ['1-1', '로그인 이후의 위협을 판단하는 AI 보안', '데모 시작', '같은 계정 · 같은 시각 · 같은 요청, 그중 하나는 탈취된 계정입니다'],
 ['C-1 · A-1', '체험할 요청 유형을 · 맡길 업무를 선택하세요', '1단계 묶음 탭', '위협 시나리오 선택 / Choose a threat scenario'],
 ['H-6 · A-6 · D-1 · M-more', '다음 단계를 선택하세요 등', '4단계 다음 확인', '다음 확인 / Next'],
 ['H-1', '요청을 보낸 주체를 선택하세요', '1단계 사람 계정 위협 탭', '위협 시나리오 선택 · 공통 요청과 두 갈래'],
 ['2-1', '공격자가 되어 대량 다운로드를 요청합니다', '2단계(S13)', '설계 자료 480건 대량 반출 요청 / Bulk export of 480 design documents'],
 ['2-2 · 4-2 · 5-2', '같은 요청이 다섯 보안에 동시에 도착했습니다 등', '3단계', '5개 보안 통제의 실시간 응답 / Live response of five security controls'],
 ['2-3', 'Contexa는 추가 인증을 요구했고, 자료는 한 건도 나가지 않았습니다', '4단계', '결과 · 판정 근거 / Result and decision evidence'],
 ['2-4', 'AI가 판단에 사용한 근거', '판정 상세 › 판정 근거', '인용 사실과 판정 근거 / Cited facts and reason codes'],
 ['4-1', '같은 요청을 정상 사용자로 보냅니다', '2단계(S13T)', '정상 사용자의 동일 반출 요청 / Same export by the legitimate user'],
 ['4-3', '같은 요청, 다른 것은 접속 환경뿐입니다', '4단계 › 같은 요청 비교 탭', '같은 요청, 다른 판정 / Same request, different decision'],
 ['4-4', '정상 사용자는 추가 인증을 거쳐 업무를 끝까지 이어 갔습니다', '4단계(S13T)', '추가 인증 통과 후 업무 완료 / Work completed after step-up'],
 ['5-1', '본인 계정으로 담당 프로젝트 문서를 내려받습니다', '2단계(S16)', '담당 프로젝트 문서 반출 요청(내부자) / Insider export of assigned documents'],
 ['5-3', '기록은 모두 정상이며, AI는 가능성을 비교했습니다', '판정 상세 › 판정 근거', '가설 평가 / Hypothesis assessment'],
 ['6-1', '에이전트가 주간 보고서를 다시 실행합니다', '2단계', '위임 기간이 끝난 뒤 보고서 에이전트 재실행 / Report agent re-run after expiry'],
 ['6-2', '에이전트 요청에 대한 다섯 보안의 판단', '3단계', '에이전트 요청별 보안 통제 응답 / Control responses per agent request'],
 ['6-7', 'Contexa는 요청 1에서 멈췄고, 기존 보안 4곳은 멈추지 못했습니다', '4단계', '결과 / Result'],
 ['6-3', '위임 범위와 실제 요청의 차이', '판정 상세 › 판정 근거', '위임 범위 대비 요청 / Request against the delegated scope'],
 ['6-4 · 6-5', '위임한 사람이 승인했고… · 책임자 응답별 결과', '4단계 › 위임자 응답', '위임자 응답별 결과 / Outcome by delegator response'],
 ['6-6 · M-stack', '요청이 한꺼번에 몰릴 때의 대응 · 같은 조회를 다섯 번 보내면?', '요청 급증 대응', '동일 요청 60건 동시 유입 / 60 identical concurrent requests'],
 ['1-2', '이 데모에서 확인할 여섯 가지', 'AI 판정 엔진 › 판정 근거 사실', '판정 근거 사실 6종 / Six classes of decision facts'],
 ['3-1 · M-how', '방금 판단이 나오기까지의 일곱 단계', 'AI 판정 엔진 › 판정 흐름', '판정 흐름 7단계 / Seven-stage decision flow'],
 ['3-2', '입력이 프롬프트의 어느 줄이 됐는가', 'AI 판정 엔진 › 판정 프롬프트', '입력값과 프롬프트 줄 대응 / Inputs mapped to prompt lines'],
 ['3-3', 'LLM이 답한 원문과, 그 답이 판정이 되기까지', '판정 상세 › 모델 응답 원문', '모델 응답 원문과 판정 적용 / Raw model response and enforcement'],
 ['7-1', '규칙을 켜도 공격과 정상 업무가 똑같이 지나갑니다', '탐지 방식 비교', '임계값 규칙 적용 결과 / Threshold rule applied'],
 ['7-2', '조건 하나를 바꿨을 때의 판단 변화', '탐지 방식 비교', '단일 조건 변경 실험 / Single-condition change'],
 ['7-3', '반복 측정에서 Contexa가 놓친 공격은 2회…', '시나리오 검증 › 통제별', '보안 통제별 미탐 · 오탐 / Misses and false positives by control'],
 ['8-1', '오늘 직접 확인한 세 가지', '4단계 진행 표시 · 판정 이력', '이 묶음에서 실행한 시나리오 n / 3 · 내 실행 기록'],
 ['8-2 · O-adopt', '우리 시스템에 도입하는 방법 · 도입하면 누구에게 무엇이…', '도입 · 연동 가이드', '도입 · 연동 가이드 · 역할별 도입 효과 / Deployment & integration'],
 ['M-learn', '03:17의 자료 내보내기, 이상한 일일까요?', 'AI 판정 엔진 › 행위 기준선', '행위 기준선 대비 판정 / Decision against the baseline'],
 ['M-learned', 'Contexa가 관리자 A에 대해 배운 것', '같은 탭', '학습된 행위 기준선(관리자 A) / Learned baseline'],
 ['M-learnafter', '무엇을 배우고, 무엇은 배우지 않을까요?', '같은 탭', '기준선 학습 범위 / Baseline learning scope'],
 ['M-timing', '응답 전에 막을까, 다음 요청부터 막을까?', 'AI 판정 엔진 › 판정 흐름', '판정 적용 시점: 동기 · 비동기 / Enforcement timing'],
 ['M-follow', '판단마다 다음에 무슨 일이 생길까요?', 'AI 판정 엔진 › 판정 흐름', '판정별 후속 조치 / Follow-up action per decision'],
 ['M-approaches', '다섯 보안 방식은 무엇을 보고, 무엇을 못 볼까요?', '탐지 방식 비교', '보안 통제별 탐지 범위 / Detection scope by control'],
 ['L-entrance', '조건 하나를 바꾸면 판단이 달라질까요?', '정책 시뮬레이터', '정책 시뮬레이터 / Policy simulator'],
 ['L-case · L-change · L-before', '어떤 상황으로 해 볼까요? · 무엇을 바꿔 볼까요? · …', '1~3단계', '기준 시나리오 · 조건 변경 · 전송 전 입력 비교'],
 ['L-send · L-result', '이 요청은 공격일까요, 정상 업무일까요? · 아직 결과가 없습니다', '4~5단계', '예상 판정 · 실행 / 실행 결과'],
 ['L-rules', '규칙을 조이면 무엇이 막히고, 풀면 무엇이 지나갈까요?', '정책 시뮬레이터 › 임계값 조정', '임계값 조정 / Threshold tuning'],
 ['L-agent', '에이전트의 요청도 같은 토큰으로 옵니다. 맡긴 일 밖이면…?', '정책 시뮬레이터 › 에이전트 정책', '에이전트 위임 정책 / Agent delegation policy'],
 ['B-summary', '기존 보안이 모두 놓친 공격, Contexa는 막았을까요?', '시나리오 검증 › 요약', '시나리오 검증 요약 / Scenario validation summary'],
 ['B-approaches', '다섯 보안은 공격을 얼마나 막고, 정상 업무를 얼마나 막았을까요?', '시나리오 검증 › 통제별', '보안 통제별 탐지율 · 오탐률 / Detection and FP rates by control'],
 ['B-cases · B-case', '상황마다 누가 제대로 처리했을까요?', '시나리오 검증 › 시나리오별', '시나리오별 결과 / Results by scenario'],
 ['B-judgment · B-reasoning', 'Contexa가 받은 공격 23회는…? · AI의 판단을 믿을 수 있을까요?', '시나리오 검증 › 판정 품질', '위협 23회 판정 결과 · 판정 근거 품질 검사'],
 ['B-limits', 'Contexa는 무엇을 놓쳤을까요?', '시나리오 검증 › 한계 · 방법', '미탐 시나리오와 측정 한계 / Misses and limits'],
 ['B-agent', '에이전트의 요청에서 Contexa는 얼마나 막았을까요?', '시나리오 검증 › 에이전트', '에이전트 시나리오 결과 / Agent scenario results'],
 ['O-videos · O-privacy', '화면별 미리보기 영상 · 개인정보 안내', '제품 투어 · 바닥', '제품 투어 · 개인정보 처리방침 / Product tour · Privacy policy'],
 ['O-replay · O-detail', '저장된 실제 기록으로 봅니다 · (모달)', '판정 이력', '공개 녹화 실행 · 판정 상세(실행 ID + 판정 뱃지)'],
]
paged_table('8 · 용어 · 문체', '64화면 제목 다시 쓰기', '질문 · 지시형 29개를 포함한 64화면 전부의 새 위치와 새 제목', [1.95, 3.85, 2.55, 3.75], TITLES)

paged_table('8 · 용어 · 문체', '문구 5,924키 전환 방법', '한 · 영 사전 각 5,924키. 질문형 147키, "세요" 92키, "판단" 512키가 0이 될 때까지', [0.6, 3.2, 8.3], [
    ['#', '단계', '내용'],
    ['1', '용어 사전 파일', 'i18n/glossary.json(정식 한 · 영 · 금지어 · 정의). 툴팁과 보안 용어집 화면이 같은 파일을 읽는다'],
    ['2', '금지어 검사', '옛 말과 W-1 · W-4 패턴(질문 · 권유 · 체험 어휘)을 사전 전체에서 찾는 시험. 목록 갱신만 사용자 승인'],
    ['3', '화면 단위로 새로 쓰기', '새 화면의 키는 새 이름 공간(screen.<메뉴>.<탭>.*)으로 새로 쓴다. 옛 키는 화면이 사라질 때 함께 지운다'],
    ['4', '사실 보존', '64화면 제목표대로 옛 화면의 사실이 새 위치에 모두 있는지 시험(P-8)'],
    ['5', '한 · 영 동시', '키를 더할 때 두 언어가 다 있어야 시험 통과(지금 규칙 유지)'],
    ['6', '검수', '화면별 사진(한 · 영 × 2폭)으로 문장 길이 · 줄바꿈 · 한 글자 줄 자동 검사 + 눈 검수']])

# ---------------------------------------------------------------- verification
paged_table('9 · 검증 · 구현 · 결정', '시안 숫자의 출처 — 지어낸 숫자 0', '모든 숫자를 실제 응답 · 원자료와 대조했다', [2.6, 5.6, 3.9], [
    ['시안', '숫자', '출처'],
    ['보안 현황 · 운영 지표 · 도입', '판정 13,733(9,932 · 2,148 · 1,136 · 517), p50 5,959ms · p95 16,321ms, 완료 6,872 · 실패 87, 방문자 2,046', '/api/stats'],
    ['보안 현황 · 판정 이력', '최근 판정 5건의 시나리오 · 정답', '/api/runs/{id}/score'],
    ['결과 · 판정 상세 · 엔진', 'run-04cdd89264f7: CHALLENGE · 0.43 · 0.78 · 10,169ms · 사실 F1~F10 · 가설 H1~H4 · 근거 코드 5 · 검사 INCOMPLETE · 157줄', 'steps/1/result · facts · anatomy · quality'],
    ['탐지 방식 비교', '규칙 조건(야간 22~06 · 500건 · 30일), 정상 실행 ALLOW · 480건', 'ThresholdRules.java · 실행 결과'],
    ['정책 시뮬레이터', '상한 11개 값별 C1 · C2 · Contexa 집계', '/api/rules/evaluate 실호출 11회'],
    ['도입 가이드', '좌표 · 어노테이션 · 모드 · 보관 기본값', 'build.gradle · README · 코어 Properties'],
    ['엔진(봉인 보관)', '모든 판정 봉인 · 깨끗한 봉인 90일(이 데모 설정)', 'showcase-workload-contexa application.yml'],
    ['표준 벤치마크', '결과 행렬 · 영향 · 구간 · 비용', 'contexa-benchmark 보고 파일 · 완료판정서'],
    ['데모 시작 · 3단계(v3)', '통제별 응답 27 · 21 · 25 · 41ms(허용 480건), Contexa 10,169ms · 0건', 'run-04cdd89264f7 result'],
    ['1단계 · 비교(v3)', 'S13T 단말 Edge 140 · Windows, 같은 대역 · 시각 · 규모 · OTP, 이탈 1/9, 위험도 0.20, 학습 48 → 49', 'run-9c74d0f95216'],
    ['1단계 내부자 · 에이전트(v3)', 'S16 문서 1건 × 3(14:20~14:22), N1 정상 · T5 · M22A · M10A 위협 · M14A 정답 미지정', 'run-d399d3a50c57 · /api/agent-cases'],
    ['데모 시작 · 2단계(v3)', '방문자당 하루 10회', 'showcase.live.visitor-daily 기본값']])

paged_table('9 · 검증 · 구현 · 결정', '검증 중 찾아 고친 시안 오류', '구현 때 같은 실수를 막는 근거 — 화면 숫자는 자동 대조 시험으로 고정한다', [4.6, 7.5], [
    ['오류', '고친 내용'],
    ['도입 가이드 "행동 기록 400일"', '포털 보관 작업 기록의 기간이었다 → 코어 기본값(봉인 90일 · 깨끗한 봉인 30일 · 표본 1% 등)'],
    ['결과 화면 "이 단말 사용 0 / 48건"', '분모가 요일 비교의 값이었다 → 원문 "0 of 20"(최근 7일)'],
    ['엔진 "계정 탈취 요청 (차단)"', '실제 판정은 추가 인증'],
    ['보안 현황 Promptfoo "진행 중"', 'S-3 완료 반영(43.6% → 55.4%)'],
    ['탐지 방식 비교 규칙 설명', '휴면(30일) 조건 누락 → 3가지 조건 모두'],
    ['판정 기록 검증 일부 항목만', '전체 결과(불완전 · 불일치 0 · 일치 19 · 확인 불가 9)'],
    ['이름 혼용', '"추가 인증 요구" · "승인 정책" → 정식 이름'],
    ['시안 글자 16종 · 버튼 5종', '9종 · 3종으로 정규화'],
    ['선택 · 상태 · AI 강조의 금색', '파랑으로(선택 카드 · 선택 행 · 스위치 · 범위 막대 · AI 단계)'],
    ['라이트 대비 미달 3곳 · 다크 1곳', '토큰 값 보정(4.5:1 이상)']])

paged_table('9 · 검증 · 구현 · 결정', '구현 단계와 관문 (승인 뒤)', 'OSS 코어는 바꾸지 않는다. 새 의존성은 Lucide 아이콘 하나(D-7)', [0.9, 6.3, 4.9], [
    ['단계', '내용', '관문'],
    ['R-0', '시안(정지 HTML, 실제 데이터)', '완료 — v2 17 + v3 체험 흐름 8 + 이 설계안, 사용자 확인'],
    ['R-1', '디자인 체계: 토큰 · 부품 · 부품 화면 · 토큰 밖 값 금지 검사', '부품 시험, 대비 검사, 두 테마'],
    ['R-2', '앱 틀: 메뉴 등록표 · 맨 위 바 · 빵가루 · 검색 · 경로 · 옛 주소 넘김', '옛 주소 전부 새 위치로, 키보드 이동'],
    ['R-3', '용어 · 문체: glossary.json, 금지어 검사, 새 이름 공간', '질문형 · 금지어 0'],
    ['R-4', '실행형: 계정 탈취 · 내부자, 에이전트, 요청 급증, 정책 시뮬레이터', '실서버 실제 전송 e2e(한 · 영)'],
    ['R-5', '조회형: 판정 이력 · 판정 상세 · 운영 지표 · 탐지 방식 비교 · 시나리오 검증', '화면 숫자 = 포털 값, 옛 화면 사실 전부'],
    ['R-5b', '표준 벤치마크: 결과 묶음 스크립트(해시 대조) · 화면', '숫자 = 보고 파일(자동 대조), PC-9 검사'],
    ['R-6', '설명형: 보안 현황 · AI 판정 엔진 · 도입 가이드 · 용어집', '같음'],
    ['R-7', '전수 검수: 전 화면 × 한 · 영 × 5폭, 자동 검사, LCP', '실패 0, 사용자 확인']])

paged_table('9 · 검증 · 구현 · 결정', '결정 요청 19개 (모두 권장: 승인)', '기획안 19절', [0.85, 11.25], [
    ['#', '결정'],
    ['D-1', '메뉴 구조(방문자 동선 순서 5묶음 13메뉴 + 바닥 2)'],
    ['D-2', '실행형은 위협 시뮬레이션 4메뉴만, 나머지는 독립 화면 + 탭'],
    ['D-3', '글자 체계 9단계(본문 15 · 표 14 · 제목 28) — AC-N6 대체'],
    ['D-4', '첫 화면 글자 수 기준(AC-N2)은 실행형에만, 조회형은 결론 카드 기준'],
    ['D-5', '다크 기본 + 라이트 테마'],
    ['D-6', '금색은 로고 · 주 동작 · 지금 위치 · Contexa 식별에만, 선택 · 링크 · AI 강조는 파랑'],
    ['D-7', '아이콘 한 벌(새 의존성: Lucide, ISC, 쓰는 아이콘만 묶음)'],
    ['D-8', '운영 지표는 지금 응답만으로, 새 값은 따로 승인'],
    ['D-9', '시안(R-0) 기준 확정 뒤 R-1부터 구현'],
    ['D-10', '표준 벤치마크와 시나리오 검증을 두 메뉴로'],
    ['D-11', '표준 벤치마크 데이터 길: 보고 파일 → 결과 묶음(해시 대조) → 포털 정적 자원'],
    ['D-12', '표준 벤치마크 표현 규칙(PC-9, 자체 지표 뱃지)'],
    ['D-13', '확장 구조: 메뉴 등록표, 언어 = 사전 + 용어 사전, 고정 주소'],
    ['D-14', '보안 업무 용어 체계(정식 한 · 영과 줄임)'],
    ['D-15', '문체 규칙과 5,924키 전환 방법(금지어 검사 포함)'],
    ['D-16', '64화면 제목 · 새 위치 대응표'],
    ['D-17', '체험 흐름: 데모 시작 첫 화면 · 집중 모드 · 안내형 4단계 · 같은 요청 비교 · 다음 확인 3개'],
    ['D-18', '보안 현황 대시보드를 없애고 수치는 운영 지표 · 데모 시작 신뢰 띠로'],
    ['D-19', '진행 표시 n / 3은 지금 있는 방문자 실행 기록으로, 응답에 없으면 따로 승인']])

s = new_slide('9 · 검증 · 구현 · 결정', '참고 — 공개 전 위험(화면 설계와 별개)', '최종 보고의 위험 항목으로 따로 올린다')
rect(s, 0.6, 1.6, 12.1, 2.2, 'surface', 'line', radius=0.04)
text(s, 0.9, 1.85, 11.5, 1.9, [[('대표 시나리오 S13(계정 탈취)의 판정이 갈린다', {'bold': True, 'color': 'text', 'size': 17})],
                               '2026-10-27 기록에서 허용 12/30, 오늘(10-31) 실행에서 허용 2/3이었다.',
                               '시안은 실제 기록을 그대로 보이므로 결과 화면 · 최근 판정에 "허용 · 미탐"이 나올 수 있다 — 숨기지 않고 시나리오 검증의 "판정이 갈리는 시나리오"로 함께 밝힌다.'], 15, 't2', spacing=1.25)

footer_all()
print(chr(10).join(WARN) or 'no layout warnings')
prs.save(TARGET)
print('slides', len(prs.slides), '->', TARGET)
