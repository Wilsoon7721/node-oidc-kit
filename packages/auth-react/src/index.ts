import { AuthCore } from '@wilsoon/auth-core';

// REACT SECTION
export const AuthProvider = () => {
  const core = new AuthCore();
  return "AuthProvider logic using core";
};
