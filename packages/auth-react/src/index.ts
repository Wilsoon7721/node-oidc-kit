import { WilsoonID } from '@wilsoon/auth-core';
import { useEffect, useState } from 'react';

export const useWilsoonAuth = (apiKey: string) => {
  const [sdk, setSdk] = useState<WilsoonID | null>(null);

  useEffect(() => {
    const instance = new WilsoonID(apiKey);
    setSdk(instance);
  }, [apiKey]);

  return { sdk };
};
