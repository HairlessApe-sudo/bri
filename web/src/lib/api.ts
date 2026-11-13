import { errorMessageForStatus } from './client-errors.mjs';

export type OrganizationNode = {
  node_id: string;
  node_type: string;
  display_name: string;
  parent_node_id: string | null;
};
export type OrganizationRelationship = {
  relationship_id: string;
  from_node_id: string;
  to_node_id: string;
  relationship_type: string;
  grants_access: boolean;
};
export type OrganizationStructure = { nodes: OrganizationNode[]; relationships: OrganizationRelationship[] };
export type KnowledgeRecord = {
  record_id: string;
  title: string;
  scope_id: string;
  validation_state: string;
  source_id: string;
  source_version_id: string;
  source_version: string;
  extraction_id: string;
  content_sha256: string;
  extractor_name: string;
  extractor_version: string;
  source_location: string;
  content: string;
};
export type SourceReference = Omit<KnowledgeRecord, 'scope_id' | 'validation_state' | 'content'>;
export type Citation = SourceReference & { excerpt: string };
export type SearchResult = { status: string; answer: string | null; citations: Citation[] };

export async function fetchApi<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, { headers: { accept: 'application/json' }, cache: 'no-store', signal });
  if (!response.ok) {
    const error = new Error(errorMessageForStatus(response.status));
    Object.assign(error, { status: response.status });
    throw error;
  }
  return response.json() as Promise<T>;
}
