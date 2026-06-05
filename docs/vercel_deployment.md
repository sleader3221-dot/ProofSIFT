# Vercel Deployment Settings

Use these exact settings for the ProofSIFT public dashboard and architecture demo.

| Setting             | Value                                             |
| ------------------- | ------------------------------------------------- |
| Framework Preset    | `Vite`                                            |
| Root Directory      | `.`                                               |
| Install Command     | `npm install`                                     |
| Build Command       | `npm run build`                                   |
| Output Directory    | `dist`                                            |
| Development Command | `npm run dev`                                     |
| Node.js Version     | Vercel default LTS is fine; Node 20+ recommended. |

The repository includes `vercel.json`:

```json
{
  "$schema": "https://openapi.vercel.sh/vercel.json",
  "buildCommand": "npm run build",
  "devCommand": "npm run dev",
  "framework": "vite",
  "installCommand": "npm install",
  "outputDirectory": "dist",
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ]
}
```

The dashboard is client-rendered with Vite and TanStack Router. The SPA rewrite is required so deep links such as `/architecture`, `/audit`, and `/benchmark` load the compiled app bundle instead of a 404.

## Local Frontend Commands

```bash
npm install
npm run dev
npm run build
npm run preview
```

The architecture diagram entrypoint is:

```text
src/routes/architecture.tsx
```
