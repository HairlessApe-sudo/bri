import io
import json
import re
import zipfile
from datetime import datetime, time
from unittest.mock import patch

import unittest
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, GradientFill, Side
from openpyxl.utils.datetime import MAC_EPOCH

from bri.ingestion._xlsx_strict_parser import StrictParseError, parse_package


PARSER = 'bri.ingestion._xlsx_strict_parser'
SHEET = 'xl/worksheets/sheet1.xml'


def package(*, iso=False, mac=False):
    workbook = Workbook(iso_dates=iso)
    if mac:
        workbook.epoch = MAC_EPOCH
    sheet = workbook.worksheets[0]
    sheet.title = 'Résumé'
    sheet.append(['  cafe\u0301  ', 'Flag'])
    sheet['A2'] = '  café  '
    sheet['B2'] = True
    sheet['A3'] = 12.5
    sheet['B3'] = datetime(2024, 2, 29, 12, 0)
    sheet['A4'] = time(6)
    stream = io.BytesIO()
    workbook.save(stream)
    with zipfile.ZipFile(stream) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


class StrictParserTests(unittest.TestCase):
    def test_requires_complete_unique_physical_header(self):
        def text(ref, label):
            return f'<c r="{ref}" t="inlineStr"><is><t>{label}</t></is></c>'

        name = text('A1', 'Name')
        for label, sheet_data in (
            ('empty', ''),
            ('late row', f'<row r="2">{text("A2", "Name")}</row>'),
            ('offset column', f'<row r="1">{text("B1", "Name")}</row>'),
            ('nontext', f'<row r="1">{name}<c r="B1"><v>1</v></c></row>'),
            ('empty text', f'<row r="1">{text("A1", "")}</row>'),
            ('whitespace text', f'<row r="1">{text("A1", "&#160;&#9;")}</row>'),
            ('missing interior', f'<row r="1">{name}{text("C1", "Other")}</row>'),
            ('missing trailing', f'<row r="1">{name}</row><row r="2"><c r="B2"><v>1</v></c></row>'),
            ('normalized duplicate', f'<row r="1">{text("A1", "  CAFÉ")}{text("B1", "cafe&#769; ")}</row>'),
            ('casefold duplicate', f'<row r="1">{text("A1", "Straße")}{text("B1", "STRASSE")}</row>'),
        ):
            with self.subTest(label=label):
                parts = package()
                parts[SHEET] = re.sub(rb'<sheetData>.*?</sheetData>',
                                      f'<sheetData>{sheet_data}</sheetData>'.encode(), parts[SHEET])
                with self.assertRaisesRegex(StrictParseError, 'header'):
                    parse_package(parts)

    def test_parse_ordinary_package(self):
        for iso, mac in [(False, False), (False, True), (True, False)]:
            self._assert_package(iso, mac)

    def test_openpyxl_presentation_does_not_change_canonical_cells(self):
        workbook = Workbook()
        sheet = workbook.active
        sheet['A1'] = 'Amount'
        sheet['A2'] = 12.5

        def render():
            stream = io.BytesIO()
            workbook.save(stream)
            with zipfile.ZipFile(stream) as archive:
                return parse_package({name: archive.read(name) for name in archive.namelist()})

        baseline = render()
        sheet.freeze_panes = 'A2'
        sheet.column_dimensions['A'].width = 18
        sheet.row_dimensions[2].height = 21
        sheet.sheet_view.showGridLines = False
        sheet.sheet_properties.tabColor = 'FF9900'
        sheet['A2'].font = Font(bold=True, color='FF7700')
        sheet['A2'].fill = GradientFill(stop=('FFFFFF', 'FF7700'))
        sheet['A2'].border = Border(left=Side(style='thin', color='FF7700'))
        sheet['A2'].alignment = Alignment(horizontal='center')
        self.assertEqual(render(), baseline)

    def _assert_package(self, iso, mac):
        parts = package(iso=iso, mac=mac)
        output = parse_package(parts)
        assert output == parse_package(dict(reversed(list(parts.items()))))
        assert json.loads(output) == {
            'version': 1,
            'worksheet': {'identity': '1', 'title': 'Résumé', 'range': 'A1:B4'},
            'rows': [
                [['text', '  cafe\u0301  '], ['text', 'Flag']],
                [['text', '  café  '], ['boolean', True]],
                [['number', '1.25e1'], ['datetime', '2024-02-29T12:00:00']],
                [['time', '06:00:00'], None],
            ],
        }


    CASES = [
        (b'<v>12.5</v>', b'<f>1+1</f><v>2</v>'),
        (b'<v>12.5</v>', b'<v>NaN</v>'),
        (b'<v>12.5</v>', b'<v>1e9999</v>'),
        (b'<row r="3">', b'<row r="3" hidden="1">'),
        (b'<sheetPr>', b'<sheetPr><extLst/>'),
        (b'</sheetData>', b'</sheetData><conditionalFormatting sqref="B2"/>'),
        (b'</sheetData>', b'</sheetData><autoFilter ref="A1:B4"/>'),
        (b'</sheetData>', b'</sheetData><mergeCells><mergeCell ref="B5:C5"/></mergeCells>'),
        (b'</sheetData>', b'</sheetData><hyperlinks><hyperlink ref="B2" location="A1"/></hyperlinks>'),
        (b'r="A4"', b'r="BM4"'),
        (b'<row r="4">', b'<row r="10001">'),
        (b'r="A4"', b'r="A3"'),
        (b'<worksheet', b'<!DOCTYPE worksheet><worksheet'),
        ('  café  '.encode(), b'x' * 4097),
        (b'<row r="3">', b'<row r="3" ht="0">'),
        (b'<sheetData>', b'<cols><col min="1" max="1" width="0"/></cols><sheetData>'),
        (b'<sheetData>', b'<cols><col min="2" max="2" style="1"/></cols><sheetData>'),
    ]
    def test_reject_unsupported_worksheet(self):
        for old, new in self.CASES:
            with self.subTest(old=old, new=new[:50]):
                self._assert_rejects_worksheet(old, new)

    def _assert_rejects_worksheet(self, old, new):
        parts = package()
        assert old in parts[SHEET]
        parts[SHEET] = parts[SHEET].replace(old, new)
        with self.assertRaises(StrictParseError):
            parse_package(parts)


    def test_ignores_dimension_and_preserves_precise_decimal(self):
        parts = package()
        parts[SHEET] = parts[SHEET].replace(b'A1:B4', b'A1:XFD1048576').replace(
            b'12.5', b'-00012.3456789012345678901234500e+002'
        )
        result = json.loads(parse_package(parts))
        assert result['worksheet']['range'] == 'A1:B4'
        assert result['rows'][2][0] == ['number', '-1.234567890123456789012345e3']


    def test_decimal_exponent_limit_matches_canonical_domain(self):
        parts = package()
        template = parts[SHEET]
        parts[SHEET] = template.replace(b'<v>12.5</v>', b'<v>-1.23e-1022</v>')
        self.assertEqual(json.loads(parse_package(parts))['rows'][2][0], ['number', '-1.23e-1022'])
        parts[SHEET] = template.replace(b'<v>12.5</v>', b'<v>-1.23e-1023</v>')
        with self.assertRaisesRegex(StrictParseError, 'numeric exponent'):
            parse_package(parts)

    def test_reject_unreachable_part(self):
        parts = package()
        parts['xl/embeddings/object.bin'] = b'not used'
        with self.assertRaises(StrictParseError):
            parse_package(parts)


    def test_reject_excel_fictitious_leap_day(self):
        parts = package()
        parts[SHEET] = re.sub(rb'(<c r="B3"[^>]*><v>)[^<]+', rb'\g<1>60.25', parts[SHEET])
        with self.assertRaises(StrictParseError):
            parse_package(parts)

    def test_relationships_and_content_types_are_binding(self):
        for part, old, new in [
            ('xl/_rels/workbook.xml.rels', b'Target="styles.xml"',
             b'TargetMode="External" Target="styles.xml"'),
            ('xl/_rels/workbook.xml.rels', b'Target="styles.xml"', b'Target="./styles.xml"'),
            ('[Content_Types].xml', b'spreadsheetml.sheet.main+xml', b'spreadsheetml.sheet.macroEnabled.main+xml'),
            ('xl/workbook.xml', b'state="visible"', b'state="veryHidden"'),
        ]:
            with self.subTest(part=part, new=new):
                parts = package()
                self.assertIn(old, parts[part])
                parts[part] = parts[part].replace(old, new)
                with self.assertRaises(StrictParseError):
                    parse_package(parts)

    def test_rejects_sparse_rectangle_before_materializing_empty_slots(self):
        parts = package()
        parts[SHEET] = parts[SHEET].replace(b'</sheetData>',
            b'<row r="10000"><c r="BL10000"><v>1</v></c></row></sheetData>')
        with self.assertRaisesRegex(StrictParseError, 'rectangular cell count'):
            parse_package(parts)

    def test_xml_limits_fire_before_document_is_finished(self):
        original = package()[SHEET].split(b'>', 1)[0] + b'>'
        for setting, limit, payload, diagnostic in [
            ('_MAX_XML_NODES', 512, b'<row/>' * 512, 'XML node count'),
            ('_MAX_XML_DEPTH', 16, b'<row>' * 16, 'XML depth'),
        ]:
            with self.subTest(setting=setting), patch(f'{PARSER}.{setting}', limit):
                parts = package()
                parts[SHEET] = original + b'<sheetData>' + payload  # Deliberately unclosed.
                with self.assertRaisesRegex(StrictParseError, diagnostic):
                    parse_package(parts)

    def test_physical_limit_counts_even_styled_blanks_before_document_end(self):
        parts = package()
        start = parts[SHEET].split(b'<sheetData>', 1)[0] + b'<sheetData>'
        blank_cells = b'<c r="A1" s="1"/><c r="B1"/><c r="C1"><v/></c>'
        parts[SHEET] = start + b'<row r="1">' + blank_cells
        with patch(f'{PARSER}._MAX_PHYSICAL_CELLS', 2):
            with self.assertRaisesRegex(StrictParseError, 'physical cell count'):
                parse_package(parts)
            parts[SHEET] = (start + b'<row r="1"><c r="A1" t="inlineStr"><is><t>Header</t></is></c></row>'
                            b'<row r="2"><c r="C2" s="1"/></row></sheetData></worksheet>')
            result = json.loads(parse_package(parts))
            self.assertEqual(result['worksheet']['range'], 'A1')
            self.assertEqual(result['rows'], [[['text', 'Header']]])

    def test_shared_string_table_aggregate_budgets_fire_before_document_end(self):
        for setting, limit, diagnostic in [
            ('_MAX_SHARED_DECODED_BYTES', 20, 'shared string decoded bytes'),
            ('_MAX_SHARED_ENCODED_BYTES', 50, 'shared string encoded bytes'),
        ]:
            with self.subTest(setting=setting), patch(f'{PARSER}.{setting}', limit):
                parts, shared = self._package_with_shared_part()
                parts[shared] = (b'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                                 + b'<si><t>' + b'&quot;' * 12 + b'</t></si>'
                                 + b'<si><t>' + b'&#x9;' * 14 + b'</t></si>')
                with self.assertRaisesRegex(StrictParseError, diagnostic):
                    parse_package(parts)

    def test_presentation_attributes_cannot_hide_unsupported_features(self):
        for part, old, new in [
            (SHEET, b'<sheetPr>', b'<sheetPr filterMode="1">'),
            (SHEET, b'<sheetPr>', b'<sheetPr unknown="anything">'),
            ('xl/workbook.xml', b'<workbookPr', b'<workbookPr refreshAllConnections="1"'),
            ('xl/styles.xml', b'<tableStyles ', b'<tableStyles payload="opaque?" '),
        ]:
            with self.subTest(part=part, new=new):
                parts = package()
                self.assertIn(old, parts[part])
                parts[part] = parts[part].replace(old, new)
                with self.assertRaises(StrictParseError):
                    parse_package(parts)

    def test_opaque_metadata_is_bounded_but_not_projected(self):
        parts = package()
        baseline = parse_package(parts)
        core = 'docProps/core.xml'
        end = b'</cp:coreProperties>'
        self.assertIn(end, parts[core])
        parts[core] = parts[core].replace(end, b'<cp:customTag>not cell data</cp:customTag>' + end)
        self.assertEqual(parse_package(parts), baseline)
        parts[core] = parts[core].replace(b'not cell data', b'a' * (256 * 1024))
        with self.assertRaisesRegex(StrictParseError, 'metadata bytes'):
            parse_package(parts)

    def test_opaque_metadata_limits_and_namespace_boundary(self):
        core = 'docProps/core.xml'
        for payload, diagnostic in [
            (b'<cp:customTag/>' * 4096, 'metadata XML node count'),
            (b'<cp:customTag>' * 16 + b'</cp:customTag>' * 16, 'metadata XML depth'),
            (b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>', 'Unsupported'),
            (b'<cp:customTag xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
             b'r:id="rId1"/>', 'Unsupported'),
        ]:
            with self.subTest(diagnostic=diagnostic):
                parts = package()
                end = b'</cp:coreProperties>'
                self.assertIn(end, parts[core])
                parts[core] = parts[core].replace(end, payload + end)
                with self.assertRaisesRegex(StrictParseError, diagnostic):
                    parse_package(parts)

    def test_explicit_empty_text_counts_as_coordinate_evidence(self):
        parts = package()
        parts[SHEET] = re.sub(rb'<sheetData>.*?</sheetData>',
            b'<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Name</t></is></c>'
            b'<c r="B1" t="inlineStr"><is><t>Value</t></is></c>'
            b'<c r="C1" t="inlineStr"><is><t>Other</t></is></c></row>'
            b'<row r="2"><c r="A2" s="1"/></row>'
            b'<row r="4"><c r="A4" t="inlineStr"/><c r="B4"><v/></c></row>'
            b'<row r="5"><c r="C5" t="inlineStr"><is><t/></is></c></row></sheetData>', parts[SHEET])
        expected = json.loads(parse_package(parts))
        self.assertEqual(expected['worksheet']['range'], 'A1:C5')
        self.assertEqual(expected['rows'][1:], [[None] * 3, [None] * 3,
                                               [['text', ''], None, None], [None, None, ['text', '']]])

    def test_date_serial_rounds_to_microseconds_ties_to_even(self):
        for serial, expected in [(b'61.00000000015625', '1900-03-01T00:00:00.000014'),
                                 (b'61.00000000046875', '1900-03-01T00:00:00.000040')]:
            with self.subTest(serial=serial):
                parts = package()
                parts[SHEET] = re.sub(rb'(<c r="B3"[^>]*><v>)[^<]+', rb'\g<1>' + serial, parts[SHEET])
                self.assertEqual(json.loads(parse_package(parts))['rows'][2][1], ['datetime', expected])
        parts = package()
        parts[SHEET] = re.sub(rb'(<c r="B3"[^>]*><v>)[^<]+', rb'\g<1>61.99999999999999999999', parts[SHEET])
        with self.assertRaisesRegex(StrictParseError, 'rounds across the day boundary'):
            parse_package(parts)

    def _package_with_shared_part(self):
        parts = package()
        content_types = '[Content_Types].xml'
        rels = 'xl/_rels/workbook.xml.rels'
        shared = 'xl/sharedStrings.xml'
        parts[content_types] = parts[content_types].replace(b'</Types>',
            b'<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-'
            b'officedocument.spreadsheetml.sharedStrings+xml"/></Types>')
        parts[rels] = parts[rels].replace(b'</Relationships>', b'<Relationship Id="rId4" Target="sharedStrings.xml" '
            b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings"/>'
            b'</Relationships>')
        return parts, shared

    def test_shared_string_expansion_is_charged_on_every_reference(self):
        parts, shared = self._package_with_shared_part()
        parts[shared] = (b'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                         b'uniqueCount="1"><si><t>' + b'x' * 4096 + b'</t></si></sst>')
        template = parts[SHEET]
        for count in (510, 511):
            rows = ''.join(f'<row r="{i}"><c r="A{i}" t="s"><v>0</v></c></row>' for i in range(1, count + 1))
            parts[SHEET] = re.sub(rb'<sheetData>.*?</sheetData>', b'<sheetData>' + rows.encode() + b'</sheetData>',
                                  template)
            if count == 510:
                result = parse_package(parts)
                self.assertLessEqual(len(result), 2_097_152)
                self.assertEqual(json.loads(result)['rows'][-1], [['text', 'x' * 4096]])
            else:
                with self.assertRaisesRegex(StrictParseError, 'output exceeds limit'):
                    parse_package(parts)
