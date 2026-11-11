# @webcrawl/client

Zero-dependency TypeScript & Node.js SDK for **[Webcrawl Anything](https://github.com/brainfish-ai/webcrawl-anything)** and **[webcrawl.app](https://webcrawl.app)**.

## Install

```bash
npm install @webcrawl/client
```

## Quickstart

```ts
import { WebcrawlClient } from "@webcrawl/client";

const client = new WebcrawlClient({
  apiKey: process.env.WEBCRAWL_API_KEY, // or run `npx webcrawl login`
});

// 1. Search the web or structured verticals (shopping, flights, hotels, real-estate, security CVEs)
const results = await client.search({
  query: "CVE-2024-3094 xz utils",
  category: "security",
  subcategory: "cve",
  limit: 5,
});

// 2. Scrape any URL into clean Markdown
const page = await client.scrape({
  url: "https://github.com/brainfish-ai/webcrawl-anything",
  formats: ["markdown"],
});

// 3. Parse PDFs, Office files (.docx, .xlsx, .pptx), or YouTube transcripts
const doc = await client.parse({
  url: "https://arxiv.org/pdf/1706.03762.pdf",
  ocr: "auto",
});

// 4. List all supported crawl & search targets
const targets = await client.targets();
```

## Documentation & Source

- **GitHub Repository:** [brainfish-ai/webcrawl-anything](https://github.com/brainfish-ai/webcrawl-anything)
- **Cloud Platform:** [https://webcrawl.app](https://webcrawl.app)
- **License:** MIT
