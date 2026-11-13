export function errorMessageForStatus(status) {
  if (status === 403) return 'Access denied for this development identity and scope.';
  if (status === 404) return 'This item is not available to the configured identity.';
  if (status === 401) return 'The development identity was not accepted by the API.';
  if (status >= 500) return 'The BRI API is unavailable. Check that the backend is running.';
  return `The request failed (HTTP ${status}).`;
}
