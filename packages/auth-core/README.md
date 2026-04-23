# WilsoonID-NodeSDK

Node.js SDK for WilsoonID.

## Installation

```bash
npm install wilsoonid-nodesdk
```

## Usage

```javascript
import { WilsoonID } from 'wilsoonid-nodesdk';

const sdk = new WilsoonID('your-api-key');
console.log(sdk.getApiKey());
```

## Development

- `npm run dev`: Start bundling in watch mode.
- `npm run build`: Build for production.
- `npm run test`: Run tests.
- `npm run lint`: Lint code.
