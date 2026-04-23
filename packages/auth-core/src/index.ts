export const hello = () => {
  return "Hello from WilsoonID SDK!";
};

export class WilsoonID {
  private apiKey: string;

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  getApiKey() {
    return this.apiKey;
  }
}
