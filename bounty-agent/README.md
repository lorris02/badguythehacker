# BountyAgent

An autonomous AI-powered bug bounty platform. Spawn agents that actively probe authorized targets for vulnerabilities, track findings in real time, and generate professional reports — all from a web dashboard.

## Stack

- **Backend** — FastAPI, PostgreSQL, Redis, asyncpg
- **Frontend** — React 18, Tailwind CSS, Vite
- **AI** — Claude (Anthropic)
- **Infra** — Docker Compose

## Features

- Register/login 
- Spawn agents against authorized targets 
- Real time agent output via WebSocket
- Findings stored per-session with severity tagging
- Downloadable reports (bug bounty & responsible disclosure formats)
