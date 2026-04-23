import { describe, it, expect } from 'vitest';
import { hello, WilsoonID } from './index';

describe('WilsoonID SDK', () => {
  it('should return a hello message', () => {
    expect(hello()).toBe("Hello from WilsoonID SDK!");
  });

  it('should initialize with an API key', () => {
    const sdk = new WilsoonID('test-key');
    expect(sdk.getApiKey()).toBe('test-key');
  });
});
