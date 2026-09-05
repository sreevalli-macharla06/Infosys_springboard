# SentinelAI Security — Dashboard UI

A modern, enterprise-grade React frontend for the AI-Assisted Threat Detection Dashboard (Milestone 1). Designed with a high-contrast dark theme inspired by platforms like CrowdStrike Falcon, Splunk, and Microsoft Sentinel.

## Screenshots

### Dashboard Overview
![Dashboard Overview](public/screenshots/overview.png)

### Threat Intelligence
![Threat Intelligence Page](public/screenshots/threat_intel.png)

### Security Analytics
![Analytics Page](public/screenshots/analytics.png)

## Features

- **React & Vite:** Lightning-fast build tooling and modern component architecture.
- **Enterprise Dark Theme:** SOC dashboard layout engineered for high data density and contrast.
- **Interactive Visualizations:** Dynamic threat distribution pie charts, top attack bar charts, and 24-hour trend lines.
- **Real-Time Monitoring:** Live telemetry display for security events, active alerts, and risk scores.
- **Live API Integration:** Fully wired to the FastAPI + MongoDB backend with automatic error degradation.

## Tech Stack

- **Framework:** React 19, Vite
- **Styling:** Tailwind CSS
- **Charts:** Chart.js, React-ChartJS-2
- **Icons:** Lucide React, React Icons
- **Routing:** React Router DOM

## Folder Structure

```
FRONTEND/
├── public/          # Static assets & screenshots
├── src/
│   ├── charts/      # Data visualization components
│   ├── components/  # Reusable UI cards, tables, and layouts
│   ├── hooks/       # Custom React hooks (useAsyncData)
│   ├── pages/       # Router page views
│   └── services/    # API integration layer
├── package.json
└── vite.config.js
```

## Installation

Install dependencies and start the development server:

```bash
npm install
npm run dev
```

Default application URL:  
**http://localhost:5173**

## Pages

- **Overview:** Executive SOC dashboard featuring KPI summary cards, AI insights summary, and key threat charts.
- **Security Events:** Interactive table of security events with multi-field filtering and CSV export.
- **Threat Intelligence:** Indicator of Compromise (IOC) monitoring with threat confidence and severity breakdown.
- **Vulnerabilities:** System CVE vulnerability tracker displaying CVSS scores and patch statuses.
- **Analytics:** In-depth security visualizations showing attack frequency, distribution, and 24-hour trends.
- **Login:** Analyst login page with client-side input validation.

## API Integration

The frontend consumes the FastAPI backend (`http://localhost:8000`) for live security data. All network calls are centralized in `src/services/api.js` and managed with consistent loading and error handling via the `useAsyncData` hook.

## Known Limitations

- **Login Page:** Currently UI-only with client-side input validation.
- **Authentication:** Full authentication (JWT / session handling) is outside the scope of Milestone 1.
