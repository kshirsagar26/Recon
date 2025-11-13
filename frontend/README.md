# Recon_FW Frontend Dashboard

A modern, dark-themed dashboard for the Recon_FW security reconnaissance framework.

## Prerequisites

- Node.js 20+ (install from [nodejs.org](https://nodejs.org/))
- npm or yarn package manager

## Installation

1. Install Node.js if you haven't already:
   ```bash
   # On Ubuntu/Debian
   sudo apt install nodejs npm
   
   # Or use nvm (recommended)
   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
   nvm install 20
   nvm use 20
   ```

2. Install dependencies:
   ```bash
   cd frontend
   npm install
   ```

## Configuration

1. Create a `.env.local` file in the frontend directory:
   ```bash
   NEXT_PUBLIC_API_URL=http://localhost:8000
   ```

   Update the URL if your FastAPI backend runs on a different port.

## Running the Development Server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## Building for Production

```bash
npm run build
npm start
```

## Project Structure

```
frontend/
├── app/
│   ├── layout.tsx          # Root layout
│   ├── page.tsx            # Main dashboard page
│   └── globals.css         # Global styles
├── components/
│   ├── Header.tsx          # Top header with search
│   ├── SummaryCards.tsx    # Metric cards
│   ├── ScanResultsTable.tsx # Data table
│   ├── VulnerabilityChart.tsx # Bar chart
│   ├── ScanProgress.tsx    # Progress sidebar
│   └── Reports.tsx         # Report buttons
├── lib/
│   ├── api.ts              # API client
│   └── types.ts            # TypeScript types
└── package.json
```

## Features

- ✅ Dark theme UI
- ✅ Summary statistics cards
- ✅ Scan results table with status badges
- ✅ Vulnerability statistics chart
- ✅ Real-time scan progress
- ✅ Search functionality
- ✅ Report generation buttons

## Connecting to Backend

The frontend uses mock data by default. To connect to your FastAPI backend:

1. Update `lib/api.ts` to use actual API endpoints
2. Ensure CORS is enabled in your FastAPI backend:
   ```python
   from fastapi.middleware.cors import CORSMiddleware
   
   app.add_middleware(
       CORSMiddleware,
       allow_origins=["http://localhost:3000"],
       allow_credentials=True,
       allow_methods=["*"],
       allow_headers=["*"],
   )
   ```

## Technologies Used

- Next.js 14 (React framework)
- TypeScript
- Tailwind CSS (styling)
- Recharts (charts)
- Lucide React (icons)
- Axios (HTTP client)

