# Vercel Deployment Settings

Use these exact settings for the ProofSIFT architecture visualizer.

| Setting | Value |
| --- | --- |
| Framework Preset | `Vite` |
| Root Directory | `.` |
| Install Command | `npm install` |
| Build Command | `npm run build` |
| Output Directory | `dist` |
| Development Command | `npm run dev` |
| Node.js Version | Vercel default LTS is fine; Node 20+ recommended. |

The repository includes `vercel.json`:

```json
{
  "framework": "vite",
  "buildCommand": "npm run build",
  "outputDirectory": "dist",
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ]
}
```

## Local Frontend Commands

```bash
npm install
npm run dev
npm run build
```

The diagram entrypoint is:

```text
src/frontend/ProofSIFTArchitectureFlow.jsx
```

