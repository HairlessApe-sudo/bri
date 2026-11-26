"""Strict scalar SpreadsheetML profile for already validated, in-memory ZIP parts.

Canonical v1 JSON contains worksheet {identity (sheetId string), title, range
(A1 notation or null)} and a rectangular rows array. Slots are null or
[type, value]; the rectangle starts at the first populated row and column.
An explicit empty string is a text value and contributes to the rectangle;
a missing cell or physically styled blank is null and does not anchor it.
Finite decimal numbers are canonicalized exactly. Numeric date/time serials
round to microseconds, ties to even, without carrying into the next day.
No display formatting, formula evaluation, or normalization of user text.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime, time, timedelta
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from xml.etree.ElementTree import Element, ParseError, TreeBuilder

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from ._xlsx_strict_schema import valid_header


class StrictParseError(ValueError):
    """Invalid, unsupported or out-of-budget XLSX (safe static diagnostic)."""


_S = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
_R = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
_P = 'http://schemas.openxmlformats.org/package/2006/relationships'
_C = 'http://schemas.openxmlformats.org/package/2006/content-types'
_A = 'http://schemas.openxmlformats.org/drawingml/2006/main'
_CORE = 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties'
_APP = 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'
_MIME = 'application/vnd.openxmlformats-officedocument.'
_REL_MIME = 'application/vnd.openxmlformats-package.relationships+xml'
_CT = '[Content_Types].xml'
_ROOT_REL = '_rels/.rels'
_BOOK_REL = 'xl/_rels/workbook.xml.rels'
_MAX_BYTES = 2_097_152
_MAX_CELLS = 100_000
_MAX_PHYSICAL_CELLS = 100_000
_MAX_XML_NODES = 350_000  # per part, including non-value elements
_MAX_XML_DEPTH = 32
_MAX_METADATA_BYTES = 256 * 1024
_MAX_METADATA_NODES = 4096
_MAX_METADATA_DEPTH = 16
_MAX_SHARED_ITEMS = 100_000
_MAX_SHARED_DECODED_BYTES = _MAX_BYTES
_MAX_SHARED_ENCODED_BYTES = _MAX_BYTES
_MAX_TEXT = 4096
_DAY_US = 86_400_000_000
_SP = '{http://www.w3.org/XML/1998/namespace}space'
_UINT = re.compile(r'0|[1-9][0-9]{0,9}')
_NUM = re.compile(r'[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[Ee][+-]?[0-9]{1,4})?')
_COORD = re.compile(r'([A-Z]{1,2})([1-9][0-9]{0,4})')
_REL_ID = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,127}')
_ESCAPE = re.compile(r'_x[0-9a-fA-F]{4}_')
_BAD_TITLE = re.compile(r'[\x00-\x1f\[\]:*?/\\]')

# Only direct, unambiguous targets in this OPC profile. Arbitrary part aliases,
# unreferenced files and per-worksheet relationships are not accepted.
_ROOT_TYPES = {
    _R + '/officeDocument': (r'xl/workbook\.xml', _MIME + 'spreadsheetml.sheet.main+xml'),
    _R + '/extended-properties': (r'docProps/app\.xml', _MIME + 'extended-properties+xml'),
    _P + '/metadata/core-properties': (
        r'docProps/core\.xml', 'application/vnd.openxmlformats-package.core-properties+xml',
    ),
}
_BOOK_TYPES = {
    _R + '/worksheet': (r'xl/worksheets/sheet[1-9][0-9]{0,9}\.xml', _MIME + 'spreadsheetml.worksheet+xml'),
    _R + '/styles': (r'xl/styles\.xml', _MIME + 'spreadsheetml.styles+xml'),
    _R + '/sharedStrings': (r'xl/sharedStrings\.xml', _MIME + 'spreadsheetml.sharedStrings+xml'),
    _R + '/theme': (r'xl/theme/theme[1-9][0-9]{0,9}\.xml', _MIME + 'theme+xml'),
}


def _require(test: object, message: str = 'Unsupported or malformed XLSX content') -> None:
    if not test:
        raise StrictParseError(message)


def _tag(namespace: str, name: str) -> str:
    return f'{{{namespace}}}{name}'


class _BoundedTree(TreeBuilder):
    """Apply budgets in parser callbacks, before forwarding to TreeBuilder."""

    def __init__(self, root_tag: str):
        super().__init__()
        self.root_tag = root_tag
        self.worksheet = root_tag == _tag(_S, 'worksheet')
        self.shared = root_tag == _tag(_S, 'sst')
        self.path: list[str] = []
        self.nodes = self.cells = self.items = self.decoded = self.encoded = self.item_bytes = 0

    def start(self, tag: str, attrs: dict[str, str]) -> Element:
        depth = len(self.path) + 1
        self.nodes += 1
        _require(depth <= _MAX_XML_DEPTH, 'XLSX XML depth exceeds limit')
        _require(self.nodes <= _MAX_XML_NODES, 'XLSX XML node count exceeds limit')
        if depth == 1:
            _require(tag == self.root_tag)
        elif self.worksheet and tag == _tag(_S, 'c'):
            self.cells += 1  # Includes styled blanks and empty <v/> cells.
            _require(self.cells <= _MAX_PHYSICAL_CELLS, 'XLSX physical cell count exceeds limit')
        elif self.shared:
            _require((depth, tag) in {(2, _tag(_S, 'si')), (3, _tag(_S, 't'))})
            if depth == 2:
                self.items += 1
                self.item_bytes = 0
                _require(self.items <= _MAX_SHARED_ITEMS, 'XLSX shared string count exceeds limit')
                self._charge_encoded(len(b'["text",""]'))
        self.path.append(tag)
        return super().start(tag, attrs)

    def _charge_encoded(self, count: int) -> None:
        self.encoded += count
        _require(self.encoded <= _MAX_SHARED_ENCODED_BYTES, 'XLSX shared string encoded bytes exceed limit')

    def data(self, text: str) -> None:
        if self.shared and len(self.path) == 3:
            size = len(text.encode('utf-8'))
            self.item_bytes += size
            self.decoded += size
            _require(self.item_bytes <= _MAX_TEXT, 'XLSX cell text exceeds limit')
            _require(self.decoded <= _MAX_SHARED_DECODED_BYTES, 'XLSX shared string decoded bytes exceed limit')
            self._charge_encoded(len(_json(text)) - 2)  # JSON escaping is additive, excluding quotes.
        super().data(text)

    def end(self, tag: str) -> Element:
        self.path.pop()
        return super().end(tag)


def _parse_xml(raw: bytes, target):
    try:
        parser = ElementTree.XMLParser(target=target, forbid_dtd=True, forbid_entities=True, forbid_external=True)
        # Bound text callback chunks independently of the maximum archive member.
        for offset in range(0, len(raw), 8192):
            parser.feed(raw[offset:offset + 8192])
        return parser.close()
    except StrictParseError:
        raise
    except (ParseError, DefusedXmlException, ValueError, LookupError):
        raise StrictParseError('Invalid XLSX XML') from None


def _xml(raw: bytes, namespace: str, root_name: str) -> Element:
    return _parse_xml(raw, _BoundedTree(_tag(namespace, root_name)))


def _attrs(node: Element, names: str = '', extra: tuple[str, ...] = ()) -> None:
    _require(node.attrib.keys() <= set(names.split()).union(extra))


def _layout(node: Element) -> None:
    _require(not (node.text or '').strip() and all(not (child.tail or '').strip() for child in node))


def _leaf(node: Element, *, text: bool = False) -> None:
    _require(len(node) == 0 and (text or not (node.text or '').strip()))


def _uint(value: str, limit: int = 4_294_967_295) -> int:
    _require(_UINT.fullmatch(value))
    number = int(value)
    _require(number <= limit)
    return number


def _bool(value: str) -> bool:
    _require(value in {'0', '1', 'false', 'true'})
    return value in {'1', 'true'}


def _unique_children(node: Element, names: str) -> dict[str, Element]:
    _layout(node)
    tags = {_tag(_S, name): name for name in names.split()}
    result = {}
    for child in node:
        name = tags.get(child.tag)
        _require(name is not None and name not in result)
        if name is not None:
            result[name] = child
    return result


def _relationships(root: Element, types: dict[str, tuple[str, str]], prefix: str):
    _attrs(root)
    _layout(root)
    by_type: dict[str, tuple[str, str]] = {}
    targets = {}
    ids = set()
    for node in root:
        _require(node.tag == _tag(_P, 'Relationship'))
        _attrs(node, 'Id Type Target TargetMode')
        _leaf(node)
        rid, kind, raw = (node.get(name, '') for name in ('Id', 'Type', 'Target'))
        _require(_REL_ID.fullmatch(rid) and rid not in ids and kind in types and kind not in by_type)
        _require(node.get('TargetMode', 'Internal') == 'Internal', 'External XLSX relationships are unsupported')
        pattern, mime = types[kind]
        target = raw[1:] if raw.startswith('/') else prefix + raw
        _require(re.fullmatch(pattern, target) and target not in targets)
        by_type[kind] = (rid, target)
        targets[target] = mime
        ids.add(rid)
    return by_type, targets


def _check_content_types(raw: bytes, targets: dict[str, str]) -> None:
    root = _xml(raw, _C, 'Types')
    _attrs(root)
    _layout(root)
    defaults = {}
    overrides = {}
    for child in root:
        _leaf(child)
        mime = child.get('ContentType', '')
        if child.tag == _tag(_C, 'Default'):
            _attrs(child, 'Extension ContentType')
            ext = child.get('Extension', '')
            _require(ext not in defaults and (ext, mime) in {('xml', 'application/xml'), ('rels', _REL_MIME)})
            defaults[ext] = mime
        else:
            _require(child.tag == _tag(_C, 'Override'))
            _attrs(child, 'PartName ContentType')
            part = child.get('PartName', '')
            _require(part.startswith('/') and part[1:] in targets and part[1:] not in overrides)
            _require(mime == targets[part[1:]])
            overrides[part[1:]] = mime
    for part, mime in targets.items():
        _require(overrides.get(part, defaults.get(part.rsplit('.', 1)[-1])) == mime)


class _OpaqueMetadata:
    """Validate the XML envelope without retaining or interpreting payloads."""

    def __init__(self, root_tag: str, namespaces: set[str]):
        self.root_tag = root_tag
        self.namespaces = namespaces
        self.nodes = self.depth = 0

    def start(self, tag: str, attrs: dict[str, str]) -> None:
        if not self.depth:
            _require(tag == self.root_tag)
        self.depth += 1
        self.nodes += 1
        _require(self.depth <= _MAX_METADATA_DEPTH, 'XLSX metadata XML depth exceeds limit')
        _require(self.nodes <= _MAX_METADATA_NODES, 'XLSX metadata XML node count exceeds limit')
        _require(tag.startswith('{') and tag[1:].split('}', 1)[0] in self.namespaces)
        _require(not any(key.startswith((f'{{{_R}}}', f'{{{_P}}}')) for key in attrs))

    def end(self, tag: str) -> None:
        self.depth -= 1

    def close(self) -> None:
        pass


def _inert(raw: bytes, namespace: str, name: str, namespaces: set[str]) -> None:
    # Only the fixed theme and document-property parts use this opaque policy.
    # They cannot contribute data or targets; relationship attributes and
    # elements from unrelated namespaces are rejected, not followed.
    _require(len(raw) <= _MAX_METADATA_BYTES, 'XLSX metadata bytes exceed limit')
    _parse_xml(raw, _OpaqueMetadata(_tag(namespace, name), namespaces))


def _string(node: Element) -> str:
    # Rich text, phonetic annotations and OOXML escaped characters are outside
    # this profile rather than silently flattened or reinterpreted.
    _attrs(node)
    _layout(node)
    _require(len(node) == 1 and node[0].tag == _tag(_S, 't'))
    text = node[0]
    _attrs(text, extra=(_SP,))
    _leaf(text, text=True)
    _require(text.get(_SP, 'default') in {'default', 'preserve'})
    value = text.text or ''
    _require(not _ESCAPE.search(value))
    _require(len(value.encode('utf-8')) <= _MAX_TEXT, 'XLSX cell text exceeds limit')
    return value


def _shared(raw: bytes) -> list[bytes]:
    root = _xml(raw, _S, 'sst')
    _attrs(root, 'count uniqueCount')
    _layout(root)

    if 'uniqueCount' in root.attrib:
        _require(_uint(root.attrib['uniqueCount']) == len(root))
    if 'count' in root.attrib:
        _require(_uint(root.attrib['count']) >= len(root))
    values = []
    for child in root:
        _require(child.tag == _tag(_S, 'si'))
        values.append(_json(['text', _string(child)]))
    return values


_DATE_FORMATS = {
    'yyyy-mm-dd': 'date', 'yy-mm-dd': 'date', 'yyyy/mm/dd': 'date',
    'mm/dd/yyyy': 'date', 'm/d/yy': 'date', 'dd/mm/yyyy': 'date',
    'yyyy-mm-dd h:mm:ss': 'datetime', 'yyyy-mm-dd hh:mm:ss': 'datetime',
    'yyyy-mm-dd h:mm:ss.000': 'datetime', 'yyyy-mm-dd hh:mm:ss.000': 'datetime',
    'yyyy-mm-dd"t"hh:mm:ss': 'datetime', 'yyyy-mm-dd"t"hh:mm:ss.000': 'datetime',
    'hh:mm:ss': 'time', 'h:mm:ss': 'time', 'hh:mm:ss.000': 'time',
    'h:mm:ss.000': 'time', 'hh:mm': 'time', 'h:mm': 'time',
}
_BUILTIN_DATE = {**dict.fromkeys(range(14, 18), 'date'), **dict.fromkeys(range(18, 22), 'time'),
                 22: 'datetime', 45: 'time', 47: 'time'}
_BUILTIN_NUMBER = {*range(14), *range(37, 45), 48, 49}


def _format_kind(fmt: int, custom: dict[int, str]) -> str:
    if fmt in _BUILTIN_DATE:
        return _BUILTIN_DATE[fmt]
    if fmt in _BUILTIN_NUMBER:
        return 'number'
    if fmt in custom:
        code = custom[fmt].lower()
        if code in _DATE_FORMATS:
            return _DATE_FORMATS[code]
        # Whitelist unambiguous numeric patterns; conditional, elapsed time,
        # locale-dependent and ambiguous date patterns are intentionally rejected.
        if re.fullmatch(r'[0#?,. %()+\-]+(?:e[+\-]0+)?', code):
            return 'number'
    raise StrictParseError('Unsupported XLSX number format')


def _styles(raw: bytes) -> list[str]:
    root = _xml(raw, _S, 'styleSheet')
    _attrs(root)
    children = _unique_children(root, 'numFmts fonts fills borders cellStyleXfs cellXfs cellStyles tableStyles colors')
    custom = {}
    if (formats := children.get('numFmts')) is not None:
        _attrs(formats, 'count')
        _layout(formats)
        if 'count' in formats.attrib:
            _require(_uint(formats.attrib['count']) == len(formats))
        for child in formats:
            _require(child.tag == _tag(_S, 'numFmt'))
            _attrs(child, 'numFmtId formatCode')
            _leaf(child)
            fmt = _uint(child.get('numFmtId', ''))
            code = child.get('formatCode', '')
            _require(fmt >= 164 and fmt not in custom and 0 < len(code) <= 256)
            custom[fmt] = code
    bases = []
    styles = []
    for name, result in [('cellStyleXfs', bases), ('cellXfs', styles)]:
        if (group := children.get(name)) is None:
            continue
        _attrs(group, 'count')
        _layout(group)
        if 'count' in group.attrib:
            _require(_uint(group.attrib['count']) == len(group))
        for child in group:
            _require(child.tag == _tag(_S, 'xf'))
            _attrs(child, 'numFmtId fontId fillId borderId xfId applyAlignment applyBorder applyFill '
                          'applyFont applyNumberFormat applyProtection quotePrefix pivotButton')
            if 'pivotButton' in child.attrib:
                _require(not _bool(child.attrib['pivotButton']))
            for element_name, element in _unique_children(child, 'alignment protection').items():
                _leaf(element)
                _attrs(element, 'locked hidden' if element_name == 'protection' else
                       'horizontal vertical textRotation wrapText shrinkToFit indent relativeIndent '
                       'justifyLastLine readingOrder')
            fmt = _uint(child.get('numFmtId', '0'))
            if name == 'cellStyleXfs':
                _require('xfId' not in child.attrib)
                bases.append(fmt)
            else:
                parent = child.get('xfId')
                if parent is not None:
                    index = _uint(parent)
                    _require(index < len(bases))
                    if 'numFmtId' not in child.attrib or not _bool(child.get('applyNumberFormat', '1')):
                        fmt = bases[index]
                elif 'applyNumberFormat' in child.attrib:
                    _require(_bool(child.attrib['applyNumberFormat']) or fmt == 0)
                result.append(_format_kind(fmt, custom))
    color = ('rgb indexed auto theme tint', '')
    border_side = ('style', 'color')
    ornaments = {
        'fonts': ('count', 'font'),
        'font': ('', 'name charset family b i strike outline shadow condense extend color sz u vertAlign scheme'),
        **dict.fromkeys('name charset family b i strike outline shadow condense extend sz u vertAlign scheme'.split(),
                        ('val', '')),
        **dict.fromkeys(('color', 'fgColor', 'bgColor', 'rgbColor'), color),
        'fills': ('count', 'fill'), 'fill': ('', 'patternFill gradientFill'),
        'patternFill': ('patternType', 'fgColor bgColor'),
        'gradientFill': ('type degree left right top bottom', 'stop'), 'stop': ('position', 'color'),
        'borders': ('count', 'border'),
        'border': ('outline diagonalUp diagonalDown', 'left right top bottom diagonal vertical horizontal start end'),
        **dict.fromkeys('left right top bottom diagonal vertical horizontal start end'.split(), border_side),
        'cellStyles': ('count', 'cellStyle'), 'cellStyle': ('name xfId builtinId iLevel hidden customBuiltin', ''),
        'tableStyles': ('count defaultTableStyle defaultPivotStyle', ''),
        'colors': ('', 'indexedColors mruColors'), 'indexedColors': ('', 'rgbColor'), 'mruColors': ('', 'color'),
    }
    for name in {'fonts', 'fills', 'borders', 'cellStyles', 'tableStyles', 'colors'} & children.keys():
        node = children[name]
        _presentation(node, ornaments)
        if 'count' in node.attrib:
            _require(_uint(node.attrib['count']) == len(node))
    return styles or ['number']


def _decimal(raw: str) -> Decimal:
    _require(len(raw) <= 256 and _NUM.fullmatch(raw), 'Invalid XLSX numeric value')
    value = Decimal(raw)
    exponent = value.as_tuple().exponent
    _require(isinstance(exponent, int) and abs(exponent) <= 1024 and abs(value.adjusted()) <= 1024,
             'XLSX numeric exponent exceeds limit')
    return value


def _scientific(value: Decimal) -> str:
    if not value:
        return '0'
    sign, digits, _ = value.as_tuple()
    text = ''.join(map(str, digits)).rstrip('0')
    mantissa = text[0] + ('.' + text[1:] if len(text) > 1 else '')
    return f'{"-" if sign else ""}{mantissa}e{value.adjusted()}'


_ISO_DATE = r'[0-9]{4}-[0-9]{2}-[0-9]{2}'
_ISO_TIME = r'[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?'


def _iso(raw: str) -> tuple[str, str]:
    try:
        if re.fullmatch(_ISO_DATE, raw):
            return 'date', date.fromisoformat(raw).isoformat()
        if re.fullmatch(_ISO_TIME, raw):
            return 'time', time.fromisoformat(raw).isoformat()
        if re.fullmatch(_ISO_DATE + 'T' + _ISO_TIME, raw):
            return 'datetime', datetime.fromisoformat(raw).isoformat()
    except ValueError:
        pass
    raise StrictParseError('Invalid or timezone-bearing XLSX date/time')


def _serial(value: Decimal, kind: str, mac: bool) -> str:
    _require(0 <= value < 3_000_000, 'XLSX date/time serial out of range')
    day = int(value)
    _require(mac or day != 60, 'Excel fictitious leap day is unsupported')
    if kind == 'time':
        _require(day == 0, 'XLSX time must be within a single day')
    elif not mac:
        _require(day >= 1, 'XLSX calendar serial out of range')
    with localcontext() as ctx:
        ctx.prec = 300
        microseconds = int(((value - day) * _DAY_US).to_integral_value(rounding=ROUND_HALF_EVEN))
    if kind == 'date':
        _require(value == day, 'XLSX date-only serial has a time component')
    else:
        _require(microseconds < _DAY_US, 'XLSX time rounds across the day boundary')
    epoch = datetime(1904, 1, 1) if mac else datetime(1899, 12, 31)
    try:
        stamp = epoch + timedelta(days=day - (not mac and day > 60), microseconds=microseconds)
    except OverflowError:
        raise StrictParseError('XLSX date/time serial out of range') from None
    if kind == 'time':
        return stamp.time().isoformat()
    if kind == 'date':
        return stamp.date().isoformat()
    return stamp.isoformat()


def _json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode('utf-8')


def _cell(node: Element, styles: list[str], shared: list[bytes], mac: bool) -> bytes | None:
    _attrs(node, 'r s t')
    style = _uint(node.get('s', '0'))
    _require(style < len(styles))
    kind = node.get('t', 'n')
    _require(kind in {'n', 'b', 's', 'inlineStr', 'd'}, 'Unsupported XLSX cell type')
    fields = _unique_children(node, 'v is')  # Reject all formula elements, with or without cache.
    if kind == 'inlineStr':
        if not fields:  # openpyxl serializes an explicit empty string this way.
            return _json(['text', ''])
        _require(fields.keys() == {'is'})
        return _json(['text', _string(fields['is'])])
    if not fields and kind == 'n':
        return None
    _require(fields.keys() == {'v'})
    payload = fields['v']
    _attrs(payload)
    _leaf(payload, text=True)
    raw = payload.text or ''
    if kind == 'n' and not raw:
        return None  # Physically styled blank.
    if kind == 's':
        index = _uint(raw)
        _require(index < len(shared))
        return shared[index]
    if kind == 'd':
        return _json(_iso(raw))
    if kind == 'b':
        _require(raw in {'0', '1'})
        return _json(['boolean', raw == '1'])
    value = _decimal(raw)
    fmt = styles[style]
    return _json([fmt, _scientific(value) if fmt == 'number' else _serial(value, fmt, mac)])


def _column(name: str) -> int:
    col = 0
    for letter in name:
        col = col * 26 + ord(letter) - ord('A') + 1
    return col


def _column_name(col: int) -> str:
    if col <= 26:
        return chr(64 + col)
    first, second = divmod(col - 1, 26)
    return chr(64 + first) + chr(65 + second)


def _presentation(node: Element, hierarchy: dict[str, tuple[str, str]]) -> None:
    """Recognize only known structure in optional display metadata."""
    pending = [node]
    while pending:
        current = pending.pop()
        _layout(current)
        attrs, names = hierarchy[current.tag.split('}', 1)[1]]
        _attrs(current, attrs)
        allowed = {_tag(_S, item) for item in names.split()}
        for child in current:
            _require(child.tag in allowed)
            pending.append(child)


def _worksheet(root: Element, styles: list[str], shared: list[bytes], mac: bool, identity: str, title: str) -> bytes:
    _attrs(root)
    children = _unique_children(root, 'sheetPr dimension sheetViews sheetFormatPr cols sheetData pageMargins')
    _require('sheetData' in children)
    display = {
        'sheetPr': ('enableFormatConditionsCalculation filterMode published syncHorizontal syncRef syncVertical '
                    'transitionEvaluation transitionEntry', 'tabColor outlinePr pageSetUpPr'),
        'tabColor': ('rgb indexed auto theme tint', ''),
        'outlinePr': ('applyStyles summaryBelow summaryRight showOutlineSymbols', ''),
        'pageSetUpPr': ('autoPageBreaks fitToPage', ''), 'dimension': ('ref', ''), 'sheetViews': ('', 'sheetView'),
        'sheetView': ('windowProtection showFormulas showGridLines showRowColHeaders showZeros rightToLeft tabSelected '
                      'showRuler showOutlineSymbols defaultGridColor showWhiteSpace view topLeftCell colorId zoomScale '
                      'zoomScaleNormal zoomScaleSheetLayoutView zoomScalePageLayoutView zoomToFit workbookViewId',
                      'pane selection'),
        'pane': ('xSplit ySplit topLeftCell activePane state', ''),
        'selection': ('pane activeCell activeCellId sqref', ''),
        'sheetFormatPr': ('baseColWidth defaultColWidth defaultRowHeight customHeight zeroHeight thickTop thickBottom '
                          'outlineLevelRow outlineLevelCol', ''),
        'cols': ('', 'col'), 'col': ('min max width style hidden bestFit customWidth outlineLevel collapsed', ''),
        'pageMargins': ('left right top bottom header footer', ''),
    }
    for name, node in children.items():
        if name != 'sheetData':
            _presentation(node, display)
    if (properties := children.get('sheetPr')) is not None:
        _require(not _bool(properties.get('filterMode', '0')), 'Filtered XLSX rows are unsupported')
    if (formatting := children.get('sheetFormatPr')) is not None:
        _require(not _bool(formatting.get('zeroHeight', '0')), 'Hidden XLSX rows are unsupported')
        for name in ('defaultRowHeight', 'defaultColWidth', 'baseColWidth'):
            if name in formatting.attrib:
                _require(_decimal(formatting.attrib[name]) > 0, 'Zero or invalid XLSX row or column size')
    if (cols := children.get('cols')) is not None:
        for col in cols:
            _require(not _bool(col.get('hidden', '0')), 'Hidden XLSX columns are unsupported')
            _require(0 < _uint(col.get('min', ''), 16384) <= _uint(col.get('max', ''), 16384))
            _require(col.get('style', '0') == '0', 'XLSX column default styles are unsupported')
            if 'width' in col.attrib:
                _require(_decimal(col.attrib['width']) > 0, 'Zero or invalid XLSX column width')
    data = children['sheetData']
    _attrs(data)
    _layout(data)
    cells = {}
    last_row = last_col = 0
    written_bytes = 0
    previous_row = 0
    for row in data:
        _require(row.tag == _tag(_S, 'row'))
        _attrs(row, 'r spans s customFormat ht hidden customHeight outlineLevel collapsed thickTop thickBot')
        _layout(row)
        _require(not _bool(row.get('hidden', '0')), 'Hidden XLSX rows are unsupported')
        if 'ht' in row.attrib:
            _require(_decimal(row.attrib['ht']) > 0, 'Zero or invalid XLSX row height')
        # Row/column default styles are not inferred for data cells.
        _require(not _bool(row.get('customFormat', '0')) and row.get('s', '0') == '0')
        row_number = _uint(row.get('r', ''), 10000)
        _require(row_number > previous_row)
        previous_row = row_number
        previous_col = 0
        for node in row:
            _require(node.tag == _tag(_S, 'c'))
            match = _COORD.fullmatch(node.get('r', ''))
            if match is None:
                raise StrictParseError('Invalid XLSX cell coordinate')
            col = _column(match[1])
            _require(int(match[2]) == row_number and previous_col < col <= 64)
            previous_col = col
            value = _cell(node, styles, shared, mac)
            if value is None:
                continue
            last_row, last_col = row_number, max(last_col, col)
            _require(last_row * last_col <= _MAX_CELLS,
                     'XLSX rectangular cell count exceeds limit')
            written_bytes += len(value)  # Shared strings charged for every reference.
            _require(written_bytes <= _MAX_BYTES, 'Canonical XLSX output exceeds limit')
            cells[row_number, col] = value
    _require(valid_header(json.loads(cells.get((1, col), b'null')) for col in range(1, last_col + 1)),
             'XLSX header must start at A1 and contain unique, nonblank text for every column')
    end = f'{_column_name(last_col)}{last_row}'
    address = 'A1' if end == 'A1' else f'A1:{end}'
    metadata = _json({'version': 1, 'worksheet': {'identity': identity, 'title': title, 'range': address}})
    # Charge exact JSON envelope, punctuation and null holes before building rows.
    prefix = b'{"rows":['
    suffix = b'],' + metadata[1:]
    area = last_row * last_col
    total = len(prefix) + len(suffix) + written_bytes + 4 * (area - len(cells)) + 2 * last_row + area - 1
    _require(total <= _MAX_BYTES, 'Canonical XLSX output exceeds limit')
    rows = (b'[' + b','.join(cells.get((row, col), b'null') for col in range(1, last_col + 1)) + b']'
            for row in range(1, last_row + 1))
    return prefix + b','.join(rows) + suffix


def parse_package(parts: dict[str, bytes]) -> bytes:
    """Parse an OPC parts snapshot; never open a file, ZIP, workbook or URL."""
    _require({_CT, _ROOT_REL, _BOOK_REL} <= parts.keys(), 'XLSX package is missing required parts')
    root_types, root_targets = _relationships(_xml(parts[_ROOT_REL], _P, 'Relationships'), _ROOT_TYPES, '')
    book_types, book_targets = _relationships(_xml(parts[_BOOK_REL], _P, 'Relationships'), _BOOK_TYPES, 'xl/')
    _require(_R + '/officeDocument' in root_types and _R + '/worksheet' in book_types)
    targets = root_targets | book_targets | {_ROOT_REL: _REL_MIME, _BOOK_REL: _REL_MIME}
    _require(parts.keys() == targets.keys() | {_CT}, 'Unsupported or missing XLSX package parts')
    _check_content_types(parts[_CT], targets)
    if (app := root_types.get(_R + '/extended-properties')) is not None:
        _inert(parts[app[1]], _APP, 'Properties', {_APP, _R.rsplit('/', 1)[0] + '/docPropsVTypes'})
    if (core := root_types.get(_P + '/metadata/core-properties')) is not None:
        _inert(parts[core[1]], _CORE, 'coreProperties', {_CORE, 'http://purl.org/dc/elements/1.1/',
                                                        'http://purl.org/dc/terms/'})
    if (theme := book_types.get(_R + '/theme')) is not None:
        _inert(parts[theme[1]], _A, 'theme', {_A})
    workbook = _xml(parts[root_types[_R + '/officeDocument'][1]], _S, 'workbook')
    _attrs(workbook)
    children = _unique_children(workbook, 'fileVersion workbookPr workbookProtection bookViews sheets definedNames calcPr')
    settings = {
        'fileVersion': 'appName lastEdited lowestEdited rupBuild',
        'workbookPr': 'date1904 dateCompatibility showObjects showBorderUnselectedTables filterPrivacy '
                      'showInkAnnotation backupFile hidePivotFieldList showPivotChartFilter checkCompatibility '
                      'autoCompressPictures defaultThemeVersion',
        'workbookProtection': 'workbookPassword workbookPasswordCharacterSet revisionsPassword '
                              'revisionsPasswordCharacterSet lockStructure lockWindows lockRevision '
                              'revisionsAlgorithmName revisionsHashValue revisionsSaltValue revisionsSpinCount '
                              'workbookAlgorithmName workbookHashValue workbookSaltValue workbookSpinCount',
        'definedNames': '',  # Defined names may carry a formula or external reference.
        'calcPr': 'calcId calcMode fullCalcOnLoad refMode iterate iterateCount iterateDelta fullPrecision '
                  'calcCompleted calcOnSave concurrentCalc concurrentManualCount forceFullCalc',
    }
    for name in settings.keys() & children.keys():
        _leaf(children[name])
        _attrs(children[name], settings[name])
    if (views := children.get('bookViews')) is not None:
        _presentation(views, {'bookViews': ('', 'workbookView'),
                              'workbookView': ('visibility minimized showHorizontalScroll showVerticalScroll '
                                               'showSheetTabs xWindow yWindow windowWidth windowHeight tabRatio '
                                               'firstSheet activeTab autoFilterDateGrouping', '')})
        _require(all(view.get('visibility', 'visible') == 'visible' for view in views))
    properties = children.get('workbookPr')
    mac = _bool(properties.get('date1904', '0')) if properties is not None else False
    sheets = children.get('sheets')
    if sheets is None or len(sheets) != 1:
        raise StrictParseError('Exactly one visible XLSX worksheet is required')
    _attrs(sheets)
    _layout(sheets)
    sheet = sheets[0]
    rid, path = book_types[_R + '/worksheet']
    _require(sheet.tag == _tag(_S, 'sheet') and sheet.get('state', 'visible') == 'visible'
             and sheet.get(_tag(_R, 'id')) == rid, 'Exactly one visible XLSX worksheet is required')
    _attrs(sheet, 'name sheetId state', (_tag(_R, 'id'),))
    _leaf(sheet)
    identity, title = sheet.get('sheetId', ''), sheet.get('name', '')
    _require(_uint(identity) > 0 and 0 < len(title) <= 31 and not _BAD_TITLE.search(title)
             and not _ESCAPE.search(title) and not title.startswith("'") and not title.endswith("'"))
    styles_part, shared_part = book_types.get(_R + '/styles'), book_types.get(_R + '/sharedStrings')
    styles = _styles(parts[styles_part[1]]) if styles_part is not None else ['number']
    shared = _shared(parts[shared_part[1]]) if shared_part is not None else []
    return _worksheet(_xml(parts[path], _S, 'worksheet'), styles, shared, mac, identity, title)
