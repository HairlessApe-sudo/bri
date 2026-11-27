export const intakePath = '/v1/intake/xlsx';
export const xlsxMedia = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
export const maxWorkbookBytes = 5_000_000;
export const xlsxUuid = /^(?!00000000-0000-0000-0000-000000000000$)[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
export const xlsxNode = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const states = ['creating', 'ready', 'processing', 'proposed', 'failed'];

export function parseIntakeReceipt(value, expectedId) {
  if (!value || typeof value.id !== 'string' || !xlsxUuid.test(value.id)
    || (expectedId && expectedId !== value.id) || !states.includes(value.state)
    || Object.keys(value).length !== 2) throw new Error('Invalid XLSX intake receipt');
  return { id: value.id, state: value.state };
}
