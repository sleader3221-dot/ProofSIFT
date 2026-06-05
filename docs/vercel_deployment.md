# Vercel Deployment Settings

Use these exact settings for the ProofSIFT full-stack dashboard.

| Setting | Value |
| --- | --- |
| Framework Preset | `TanStack Start` |
| Root Directory | `.` |
| Install Command | `npm install` |
| Build Command | `npm run build` |
| Output Directory | Leave empty / framework default |
| Development Command | `npm run dev` |
| Node.js Version | Vercel default LTS is fine; Node 20+ recommended. |

The repository includes `vercel.json`:

```json
{
  "$schema": "https://openapi.vercel.sh/vercel.json",
  "buildCommand": "npm run build",
  "devCommand": "npm run dev",
  "framework": "tanstack-start",
  "installCommand": "npm install"
}
```

Do not set the output directory to `dist` or `.vercel/output/static`. TanStack Start with Nitro emits Vercel Build Output API files into `.vercel/output`; Vercel must deploy that full output, including the server function route, not only the static assets.

## Local Frontend Commands

```bash
npm install
npm run dev
npm run build
```

The diagram entrypoint is:

```text
src/routes/architecture.tsx
```

