# Proxy & VPN Detector

## Overview

A web-based security application that analyzes IP addresses to detect VPN, proxy, and Tor connections. The system provides real-time threat assessment, geographic location mapping, WHOIS records lookup, and historical analysis tracking. Designed for fraud prevention, geo-restriction enforcement, and security policy compliance.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture

**Framework & Build System:**
- React 18 with TypeScript running on Vite for fast development and optimized production builds
- Wouter for lightweight client-side routing
- TanStack Query (React Query) for server state management with aggressive caching strategies

**UI Component System:**
- Shadcn/ui component library with Radix UI primitives
- Material Design principles adapted for security-focused interfaces
- Tailwind CSS for utility-first styling with custom design tokens
- Theme system supporting light/dark modes via context provider

**State Management:**
- Server state: TanStack Query with configurable staleTime and refetch policies
- Client state: React hooks and context (theme preferences)
- Form state: React Hook Form with Zod validation

**Key UI Features:**
- Asymmetric dashboard layout (70/30 split: main analysis panel vs. sidebar)
- Real-time IP analysis with risk score visualization
- Interactive geographic mapping using React Leaflet
- Expandable WHOIS record accordions
- Searchable analysis history table with pagination
- Recent scans sidebar with quick stats

### Backend Architecture

**Runtime & Framework:**
- Node.js with Express 5 server
- TypeScript with ES modules throughout
- HTTP server with potential for WebSocket upgrades

**API Design:**
- RESTful endpoints for IP analysis operations
- Request/response validation using Zod schemas
- Centralized error handling and logging middleware
- CORS support for cross-origin requests

**Core Services:**
- IP Analysis Engine: Generates mock detection data with deterministic risk scoring based on IP characteristics
- Detection Logic: Evaluates VPN/proxy/Tor patterns using known provider lists, datacenter identification, and ISP analysis
- Risk Calculation: Multi-factor scoring system (0-100 scale) combining VPN, proxy, Tor, and datacenter indicators
- Threat Level Classification: Four-tier system (low/medium/high/critical) derived from risk scores

**Caching Strategy:**
- In-memory cache with configurable TTL (5 minutes default)
- Prevents redundant analysis of recently scanned IPs
- Returns cached analysis with whois data when available
- Improves response times and reduces computational overhead

### Data Storage

**Current Implementation:**
- In-memory storage using Map data structures
- Volatile storage suitable for development and testing
- Separate collections for IP analyses, WHOIS records, and cached results

**Schema Design (PostgreSQL-ready):**
- `ip_analyses` table: Core analysis results with geographic data, threat indicators, ISP information
- `whois_records` table: Domain registration and network allocation data
- Drizzle ORM configured for PostgreSQL with type-safe schema definitions
- Migration support via Drizzle Kit

**Data Models:**
- IP Analysis: Comprehensive threat assessment including risk score, detection flags, geolocation, network metadata
- WHOIS Record: Registration details, nameservers, contact information, network ranges
- Scan Statistics: Aggregated metrics for dashboard quick stats

### Security & Validation

**Input Validation:**
- Zod schemas for IP address format validation (IPv4/IPv6)
- Request body validation at API boundaries
- Type-safe data transformations using Drizzle-Zod

**Detection Methodology:**
- Known VPN provider identification (NordVPN, ExpressVPN, ProtonVPN, etc.)
- Datacenter detection (AWS, Google Cloud, Azure, DigitalOcean, etc.)
- Suspicious ISP flagging (hosting providers commonly used for proxies)
- Deterministic mock scoring based on IP octets for consistent testing

### Build & Deployment

**Development Workflow:**
- Vite dev server with HMR for frontend
- TSX for running TypeScript server files
- Concurrent frontend/backend development

**Production Build:**
- ESBuild for server bundling with selective dependency bundling
- Vite for optimized client build with code splitting
- Static file serving from Express for SPA routing
- Single distribution directory for deployment

**Configuration:**
- Environment-based database URL configuration
- TypeScript strict mode with path aliases
- Modular build script for client/server separation

## External Dependencies

### Third-Party UI Libraries
- **Radix UI**: Accessible component primitives (dialogs, dropdowns, tooltips, accordions)
- **Leaflet**: Interactive map visualization for IP geolocation
- **Lucide Icons**: Consistent icon system throughout the application
- **React Hook Form**: Form state management with validation
- **date-fns**: Date formatting and manipulation

### Database & ORM
- **Drizzle ORM**: Type-safe PostgreSQL ORM with migration support
- **Neon Serverless**: PostgreSQL database driver (configured but not actively used in current implementation)
- **connect-pg-simple**: PostgreSQL session store for Express (included but sessions not implemented)

### Development Tools
- **Vite**: Build tool and development server
- **ESBuild**: Fast JavaScript bundler for production builds
- **TypeScript**: Type safety across frontend and backend
- **Tailwind CSS**: Utility-first CSS framework with PostCSS

### Future Integration Points
- IP intelligence APIs (IPQualityScore, AbuseIPDB, IPInfo) for real detection capabilities
- Redis for distributed caching in production environments
- Session management with Express session and PostgreSQL store
- Rate limiting middleware for API protection