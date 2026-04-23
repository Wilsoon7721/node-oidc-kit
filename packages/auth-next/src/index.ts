import { WilsoonID } from '@wilsoon/auth-core';

export const createNextAuth = (apiKey: string) => {
  const sdk = new WilsoonID(apiKey);
  
  return {
    middleware: () => {
      console.log('Next.js Middleware logic with WilsoonID');
    },
    sdk
  };
};
