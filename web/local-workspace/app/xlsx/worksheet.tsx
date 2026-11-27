import type { parseWorksheet } from '../../xlsx-governance.mjs';

export type Worksheet = ReturnType<typeof parseWorksheet>;

function coordinate(row: number, column: number) {
  let letters = '';
  while (column > 0) {
    column--;
    letters = String.fromCharCode(65 + column % 26) + letters;
    column = Math.floor(column / 26);
  }
  return letters + row;
}

export function WorksheetView({ data }: { data: Worksheet }) {
  const rows = new Map<number, Worksheet['cells']>();
  for (const cell of data.cells) {
    const cells = rows.get(cell.row);
    if (cells) cells.push(cell);
    else rows.set(cell.row, [cell]);
  }
  return <section className="content-panel" aria-label="Worksheet evidence">
    <h2>Worksheet evidence</h2>
    <p>Worksheet {data.sheet_title} · Sheet ID {data.sheet_id} · <code>{data.cell_range}</code></p>
    <div className="table-wrap"><table aria-label="Worksheet cells">
      <thead><tr><th scope="col">Row</th><th scope="col">Cells</th></tr></thead>
      <tbody>{[...rows].map(([row, cells]) => <tr key={row}>
        <th scope="row">{row}</th><td><dl>{cells.map(({ column, value }) => {
          const cell = coordinate(row, column);
          return <div key={cell}><dt><code>{cell}</code> · {value?.[0] ?? 'blank'}</dt>
            <dd className="breakable" style={{ whiteSpace: 'pre-wrap' }}>{value === null ? '' : String(value[1])}</dd></div>;
        })}</dl></td>
      </tr>)}</tbody>
    </table></div>
  </section>;
}
