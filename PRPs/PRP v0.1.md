# Product Requirements & Plan (PRP) — **EventQR** *(working name)*

Nice — I filled your template and shaped it around the essential features you gave. I chose a pragmatic, iterative stack (React + Tailwind in front, Node.js/Express + PostgreSQL in back) and mapped the strict agent workflow and handoff files you requested. Read, copy, paste, iterate.

---

# Purpose

A prompt-optimized PRP for AI agents to implement a QR-ticketing app in a strict multi-phase workflow. The PRP contains full context, validation loops, explicit handoffs, and scope control so agents can produce working code through iterative refinement.

---

# Core Principles

1. **Context is Crucial** — every handoff file contains required docs, API contracts, examples, and caveats.
2. **Validation Loops** — automated tests and manual checks listed for each phase (unit tests + simple curl examples).
3. **Information Dense** — use the project’s conventions (React + TypeScript, Tailwind, Express, PostgreSQL).
4. **Progressive Success** — ship minimal working features first (MVP: auth, event creation, single-ticket purchases with MP, QR email).
5. **Agent Workflow Discipline** — follow the chain exactly; each agent writes handoff artifacts consumed by the next.
6. **Global Rules** — obey project rules (e.g., no token economy for MVP, single payment method, online-only validation).

---

# Project Overview

### App Requirements & General Idea

**Project Name:** `EventQR` *(placeholder — changeable)*

**Core Concept:** Simple event-ticketing platform for businesses to sell single-type events with QR-only tickets, Mercado Pago checkout, and online QR validation by staff via mobile app. Regular user accounts only; 16-word phrase used as account recovery / wallet-style identifier (no tokens at MVP).

**Primary Requirements:**

* Basic Authentication using a 16-word phrase (wallet-inspired).
* Business accounts can create events; each event has a single ticket type.
* Ticket purchases via Mercado Pago only; buyer receives QR by email.
* QR scanning app for staff (Android first) with online validation only.
* Web dashboard for event creation, basic sales reporting, and ticket validation status.

**User Stories:**

* As a **business owner**, I want to create an event and publish one ticket type so attendees can buy a ticket quickly.
* As an **attendee**, I want to buy a ticket using Mercado Pago and receive a QR by email so I can enter the event.
* As an **event staff member**, I want to validate a ticket by scanning its QR on my mobile app so I can allow entry.
* As an **admin**, I want to see basic sales reporting per event so I can track performance.

**Success Criteria:**

* 1. Able to create an event, sell at least one ticket, and deliver QR by email end-to-end.
* 2. Staff can validate a real-time QR via mobile scanner and the system marks ticket as used (online).
* 3. Dashboard shows sales count and revenue for each event.

---

# Technology Stack

**Frontend:**

* Framework: **React** (TypeScript)
* Styling: **Tailwind CSS**
* State Management: **React Query** (for server state) + Context API for auth session
* Build Tool: **Vite**

**Mobile (Scanner):**

* Android: **React Native** (Expo or bare workflow) or a small native Android app (choice documented in Phase 0)
* iOS: planned later

**Backend:**

* Runtime: **Node.js** (LTS)
* Framework: **Express** (minimal, familiar)
* Language: **TypeScript**
* Database: **PostgreSQL**
* Authentication & Session: JWT for session tokens + server-side storage of 16-word phrase metadata (see security notes)
* Email: transactional email provider (e.g., SendGrid / Postmark) — pick one in devops notes
* Payments: **Mercado Pago** integration (checkout preference: server-side order creation -> client redirect / SDK)

**DevOps & Tools:**

* Package Manager: **pnpm**
* Testing: **Vitest** (frontend & backend unit), **Playwright** for e2e (optional), simple curl checks for manual validation
* Deployment: Docker containers; staging on Heroku / Render / Railway / Docker + DigitalOcean (team choice)
* CI: GitHub Actions (lint, build, tests)
* Linters / Formatters: ESLint, Prettier, TypeScript strict mode

---

# Context

You have an agent repo available (paste into `/agents/`), e.g.:

```
/agents
  /app-flow-agent
  /ux-researcher
  /ui-designer
  /functionality-tester
  /backend-architect
  /frontend-developer
  /whimsy-injector
```

(Agent repository metadata should be inserted in `/agents/AGENT_METADATA.md`.)

---

# Agent Execution Order (concrete)

```
app-flow-agent → ux-researcher → ui-designer → functionality-tester → backend-architect → frontend-developer → whimsy-injector
```

**Agent names used in this PRP** (changeable):

* App Flow Agent: `app-flow-agent`
* UX Agent: `ux-researcher`
* UI Agent: `ui-designer`
* Testing Agent: `functionality-tester`
* Backend Agent: `backend-architect`
* Frontend Agent: `frontend-developer`
* Whimsy Injector: `whimsy-injector` (independent)

**Special Notes**

* `whimsy-injector` reads final code, adds optional UI easter-egg styles — it does not break contracts.

---

# Exact Scope (MVP) — **Define Exact Scope**

**Included (MVP):**

* Basic user registration/login using 16-word phrase system (wallet-inspired); regular user accounts only.
* Business account flag (on-boarding manual toggle in DB) to create events.
* Event creation UI + backend API (title, date/time, location text, capacity optional, price).
* Single ticket type per event (name, price, quantity).
* Purchase flow using Mercado Pago only (sandbox + production keys).
* Email delivery of PDF/PNG QR ticket upon successful payment (QR encodes ticket id + signature).
* Web dashboard: event creation, list events, view tickets sold, basic sales reporting (count, revenue).
* Mobile scanner app (Android first): simple login as staff, scan QR, call backend to validate → mark ticket used.
* Online validation only (scanner requires internet).
* No resale, no secondary marketplace; purchases are direct only.

**Excluded (cut from MVP):**

* Token (crypto) system / tokenized tickets — add later.
* Multiple payment methods — only Mercado Pago initially.
* P2P transfers of tickets.
* Offline validation mode.
* Complex role system (keep simple staff vs business vs admin).
* Excel bulk operations for now.

---

# Security & Data Considerations (short)

* **16-word phrase**: treat as a recovery/ID phrase. *Do not* store plaintext. Store a salted hash (use Argon2 / bcrypt) or derive a server-side asymmetric key from it and store the public link. Provide clear UX warnings that the phrase is the user's recovery only. Recommend client-side generation & optional encrypted backup. For MVP: generate on server, show to user once, require copy to proceed; store only a one-way hash on server and an encrypted backup if user opts in. Document this in `/handoff/app_flow.md`.
* **Payment**: do not store raw card data. Use Mercado Pago SDK best practices.
* **QR token**: include ticket id + server signature (HMAC with server secret) to prevent forgery.
* **Email**: use verified domain and templates for transactional emails.
* **GDPR/Privacy**: minimal PII; store only necessary buyer info (email, name).

---

# Design File Structure (where agents read/write)

```
/repo-root
  /agents                       # agent implementations + metadata
  /handoff                      # agent handoff files (md)
    /app_flow.md
    /ux_plan.md
    /ui_design.md
    /test_strategy.md
    /api_implementation.md
  /src
    /backend
      /src
        /controllers
        /services
        /routes
        /models
        /db
        /tests
      Dockerfile
      package.json
    /frontend
      /web-app
        /src
          /components
          /pages
          /hooks
          /styles (tailwind)
        vite.config.ts
      /mobile-scanner
        (React Native / Expo project or Android native stub)
  /scripts
    db-migrations
    seed
  /docs
    README.md
    SECURITY.md
    DEPLOY.md
  /ci
    github-actions.yaml
```

**Handoff files (required):**

* `/handoff/app_flow.md` — produced by `app-flow-agent` (architecture, data flow, API contracts).
* `/handoff/ux_plan.md` — produced by `ux-researcher` (user flows, wireframes, acceptance criteria).
* `/handoff/ui_design.md` — produced by `ui-designer` (components, Tailwind tokens, example screens).
* `/handoff/test_strategy.md` — produced by `functionality-tester` (tests + curl manual checks).
* `/handoff/api_implementation.md` — produced by `backend-architect` (actual API endpoints implemented).
* Final frontend writes into `/src/frontend/web-app/...` and references `/handoff/*` artifacts.

---

# Phase-by-Phase Development Workflow (Phases 0 → 5)

> Each phase must write its handoff file into `/handoff/` 

### Phase 0: App Flow & Architecture

* **Agent:** `app-flow-agent`
* **Reads:** App idea, scope doc, requirements, tech stack
* **Writes:** `/handoff/app_flow.md`
* **Output (deliverables):**

  * High-level architecture diagram (text + ASCII flow), data flows, sequence diagrams for purchase + validation.
  * API contract skeleton (OpenAPI minimal): auth endpoints, events, tickets, payment webhook, ticket validation.
  * DB schema draft: users, events, tickets, payments, validation_logs.
  * Security notes for 16-word phrase handling + QR signing scheme.
  * Acceptance: reviewers can run `curl /health` and `curl /openapi.json` (mock).

### Phase 1: UX & Planning

* **Agent:** `ux-researcher`
* **Reads:** `/handoff/app_flow.md`, App idea, scope doc, requirements
* **Writes:** `/handoff/ux_plan.md`

* **Output:**

  * User flows: register -> buy -> receive QR; business create event -> view sales; staff validate QR.
  * Low-fidelity wireframes in Markdown (ASCII + links to images if available).
  * Page list & acceptance for each screen (what must be visible).
  * Handoff to UI: list of components required.

### Phase 2: UI Design

* **Agent:** `ui-designer`
* **Reads:** `/handoff/ux_plan.md`
* **Writes:** `/handoff/ui_design.md`

* **Technology Focus:** Tailwind CSS, React components
* **Output:**

  * Component library spec (Button, Input, Page layout, EventCard, TicketCard, QR display modal, Scanner screen).
  * Tailwind tokens: spacing, colors, typography.
  * Example pages in JSX-like pseudo-code (no runtime code) + animations/micro-interactions notes.
  * Acceptance: component specs with sample props and visual snapshots.

### Phase 3: Functionality Testing

* **Agent:** `functionality-tester`
* **Reads:** `/handoff/ui_design.md`, `/handoff/app_flow.md`
* **Writes:** `/handoff/test_strategy.md`

* **Technology Focus:** Vitest, simple e2e test plan
* **Output:**

  * Test matrix: unit tests for API contract, integration tests for payment webhook (mock Mercado Pago), e2e scenario (buy -> email delivery mock -> validate QR).
  * Example test code snippets and commands (Vitest + node-based integration tests + curl manual checks).
  * Acceptance criteria: tests for these endpoints must exist and be runnable locally with `pnpm test`.

### Phase 4: Backend Development

* **Agent:** `backend-architect`
* **Reads:** `/handoff/app_flow.md`, `/handoff/test_strategy.md`
* **Writes:** `/src/backend/...`, `/handoff/api_implementation.md`

* **Technology Focus:** Express, PostgreSQL, TypeScript
* **Output:**

  * Implement core APIs: auth, events CRUD (create minimal), purchase flow (server creates MP preference/order), webhook endpoint to confirm payment -> create ticket record -> send QR email.
  * Implement QR HMAC signing/verification endpoints.
  * DB migrations and seed scripts (example seed business account + sample event).
  * Local dev instructions and sample `.env.example`.
  * Acceptance: local dev can run backend with `pnpm start:dev`, create event via curl, and simulate Mercado Pago webhook (curl) to produce a ticket and QR (email can be logged to console in dev).

### Phase 5: Frontend Development

* **Agent:** `frontend-developer`
* **Reads:** `/handoff/ui_design.md`, `/handoff/api_implementation.md`, `/handoff/test_strategy.md`
* **Writes:** `/src/frontend/web-app/...` and minimal `/src/mobile-scanner` scaffold

* **Technology Focus:** React + TypeScript, Tailwind, React Query
* **Output:**

  * Web app pages: login/phrase generation, event list, event page (buy button), dashboard (create event + sales report), my tickets (display QR).
  * Payment flow: minimal client to call backend to create Mercado Pago preference then redirect / open checkout per MP SDK guidance.
  * QR display component (downloadable PNG option).
  * Mobile scanner: small React Native app that logs into staff role, uses camera to scan QR, calls backend validation endpoint, shows validation result.
  * Acceptance: full end-to-end happy path works in dev environment (using Mercado Pago sandbox keys), plus tests from `test_strategy.md` pass.

---

# Phase-Specific Agent Prompts (concrete)

> Each agent receives a specific prompt and must produce the specified files.

### Phase 0 prompt (for `app-flow-agent`)

Produce `/handoff/app_flow.md` containing:

* Architecture ASCII diagram + explanation.
* API OpenAPI minimal spec for: `/auth/register`, `/auth/login`, `/events`, `/events/:id/buy`, `/payments/webhook`, `/tickets/:id/qr`, `/tickets/:id/validate`.
* DB schema SQL for users, events, tickets, payments, validation_logs.
* Security notes on 16-word phrase and QR HMAC scheme.

  Acceptance: reviewers can read the file and mock the API spec.

### Phase 1 prompt (for `ux-researcher`)

Produce `/handoff/ux_plan.md` containing:

* User flows for buyer, business, staff.
* Low-fi wireframes for login, event list, buy flow, dashboard, scanner.
* Component list for UI agent.


### Phase 2 prompt (for `ui-designer`)

Produce `/handoff/ui_design.md` containing:

* Tailwind config (tokens).
* Component API (props, variants) for core components.
* Visual spec snapshots (Markdown + placeholder images).
* Handoff notes for frontend dev.

### Phase 3 prompt (for `functionality-tester`)

Produce `/handoff/test_strategy.md` containing:

* Unit & integration tests required (file paths + sample test cases).
* Manual curl sequences for key flows (create event, simulate payment webhook, validate QR).
* Test data seeds and acceptance rules.

### Phase 4 prompt (for `backend-architect`)

Produce `/src/backend/` implementation and `/handoff/api_implementation.md` containing:

* Implemented endpoints and example curl commands for testing.
* DB migrations and sample seed data.
* How to run locally and sample env file.

  Acceptance: run backend locally, call endpoints to create event and simulate payment webhook producing a ticket.

### Phase 5 prompt (for `frontend-developer`)

Produce `/src/frontend/web-app/*` and mobile scanner scaffolding:

* Implement pages and components per `ui_design.md`.
* Integrate with backend APIs; use React Query.
* Provide local dev instructions and run script.

  Acceptance: open web-app, login, create event (business), buy ticket (sandbox), see QR, scan with mobile scanner app to validate.

---

# DB Schema (initial draft)

```sql
-- users
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE,
  name text,
  is_business boolean DEFAULT false,
  phrase_hash text NOT NULL, -- hashed 16-word phrase
  created_at timestamptz DEFAULT now()
);

-- events
CREATE TABLE events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid REFERENCES users(id),
  title text NOT NULL,
  description text,
  start_at timestamptz,
  end_at timestamptz,
  location text,
  price_cents integer NOT NULL,
  capacity integer,
  created_at timestamptz DEFAULT now()
);

-- tickets
CREATE TABLE tickets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid REFERENCES events(id),
  buyer_email text,
  buyer_name text,
  price_cents integer,
  status text DEFAULT 'purchased', -- purchased, used, refunded
  mp_payment_id text,
  qr_signature text, -- HMAC of ticket id + secret
  created_at timestamptz DEFAULT now()
);

-- payments
CREATE TABLE payments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id uuid REFERENCES tickets(id),
  mp_id text,
  amount_cents integer,
  status text,
  raw_payload jsonb,
  created_at timestamptz DEFAULT now()
);

-- validation_logs
CREATE TABLE validation_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id uuid REFERENCES tickets(id),
  staff_id uuid REFERENCES users(id),
  validated_at timestamptz DEFAULT now(),
  result text,
  note text
);
```

---

# API Contract (summary)

* `POST /auth/register` — body: `{ email?, name?, generatePhrase: true }` → returns `{ phrase (once), userId, token }`
* `POST /auth/login` — body: `{ email, phrase? }` or email+password (optional) → returns token
* `POST /events` — auth(business): create event
* `GET /events` — list
* `POST /events/:id/buy` — body: `{ buyer_name, buyer_email }` → create order, returns Mercado Pago preference id / checkout URL
* `POST /payments/webhook` — Mercado Pago webhook to confirm payment → backend creates ticket and sends email containing QR
* `GET /tickets/:id/qr` — returns QR image or data (auth required / or tokenized link)
* `POST /tickets/:id/validate` — staff scanner sends QR payload → backend validates HMAC + status, marks used if valid.

(Full OpenAPI file is produced by `app-flow-agent` in `/handoff/app_flow.md`.)

---

# QR Scheme (simple)

* QR payload: base64 of `{ ticketId, mpPaymentId, signature }`
* Signature = HMAC_SHA256(server_secret, ticketId + mpPaymentId)
* Validation: scanner app scans → sends payload to `POST /tickets/:id/validate` with signature; backend recomputes HMAC and checks ticket status.

---

# Testing & Validation (quick list)

**Mandatory automated checks**

* Unit tests for signature generation/validation.
* Test for DB migrations (schema sanity).
* Endpoint smoke tests: `/health`, `/openapi.json`.
* Mock webhook test: simulate Mercado Pago webhook to ensure ticket creation + email action triggers.

**Manual checks (curl)**

* Create business user: `curl -X POST /auth/register ...`
* Create event: `curl -X POST /events ...`
* Buy flow: `curl -X POST /events/:id/buy ...` (simulate checkout)
* Simulate webhook: `curl -X POST /payments/webhook --data '{...}'`
* Verify ticket creation and call `/tickets/:id/qr`
* Scan QR via mobile scanner (dev mode: paste QR string into scanner app debug screen)

---

# Final Validation Checklist (for reviewers / CI)

* [ ] Manual API health check passes (`GET /health`).
* [ ] Purchase flow: POST buy -> simulate webhook -> ticket row exists.
* [ ] Email / QR output appears in dev logs or transactional service.
* [ ] Scanner validation: `POST /tickets/:id/validate` marks ticket used.
* [ ] Error cases handled (invalid signature, reused ticket).
* [ ] Logs are informative but not noisy; privacy maintained.
* [ ] Documentation updated: `README.md`, `DEPLOY.md`, `SECURITY.md`.

* [ ] Requirements satisfied (see "Included" list).

---

# Anti-Patterns to Avoid (reiterated)

* No token economy for MVP.
* Do not implement P2P or offline scanning.
* Avoid hardcoding secrets; use env.
* Don’t store sensitive payment details.
* Keep 16-word phrase handling secure and documented.

---

# Suggested Milestones (sprint-sized)

1. Phase 0 & 1 complete + review (2–3 days)
2. Phase 2 design + component spec (2 days)
3. Phase 4 minimal backend (auth, events, payments webhook mock) + dev email logging (4–6 days)
4. Phase 5 frontend basic flows (login, event create, buy stub) (4–6 days)
5. Mobile scanner basic validation app (2–4 days)
6. Testing, polish, deploy to staging (2–4 days)

> (Adjust to team velocity — these are guidance milestones, not strict deadlines.)

---

# Deliverables (what each agent must leave behind)

* `app-flow-agent` → `/handoff/app_flow.md` (OpenAPI + DB schema)
* `ux-researcher` → `/handoff/ux_plan.md` (flows + wireframes)
* `ui-designer` → `/handoff/ui_design.md` (Tailwind tokens + components)
* `functionality-tester` → `/handoff/test_strategy.md` (tests + curl checks)
* `backend-architect` → `/src/backend/...` + `/handoff/api_implementation.md`
* `frontend-developer` → `/src/frontend/web-app/...` + mobile scanner skeleton
* `whimsy-injector` → optional UI easter-egg files (nonblocking)

---

# Notes & Recommendations (ops + future)

* For email, start by logging email HTML to console; add a provider for staging/production.
* Consider hosting: Heroku/Render for backend + Vercel for frontend; mobile scanner in Play Store later.
* Add analytics (lightweight) once MVP stable.

---

If you want, I can now:

* Generate the first `/handoff/app_flow.md` draft and API OpenAPI skeleton, or
* Generate the DB migration SQL + sample seeds, or
* Produce the exact `README.md` + `.env.example` for this plan.

Which one do you want me to produce right now? (I’ll produce it immediately in this conversation.)
