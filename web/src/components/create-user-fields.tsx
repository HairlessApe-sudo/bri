import { useId } from 'react';

export function CreateUserFields() {
  return <>
    <label>Display name<input name="display_name" type="text" autoComplete="off" required /></label>
    <label>Email<input name="email" type="email" autoComplete="off" required /></label>
  </>;
}

export function DisabledCreateUser() {
  const reasonId = useId();
  return <details className="directory-create">
    <summary>Create user</summary>
    <p id={reasonId} className="auth-unavailable">User creation is disabled in this release. A safe invitation and account setup flow is not available.</p>
    <fieldset disabled className="auth-form directory-create-fields" aria-describedby={reasonId}>
      <CreateUserFields />
      <button type="button" className="auth-submit">Create user</button>
    </fieldset>
  </details>;
}
