import { AuthCore } from '@wilsoon/auth-core';

export const handleAuth = () => {
  const core = new AuthCore();
  return "Next.js Auth Handler using core";
};
