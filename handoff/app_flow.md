# EventQR — Architecture & App Flow Documentation

**Version:** 1.0
**Last Updated:** 2025-11-05
**Status:** Implementation Ready

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [System Components](#system-components)
3. [Data Flow Diagrams](#data-flow-diagrams)
4. [API Contract (OpenAPI Specification)](#api-contract-openapi-specification)
5. [Database Schema](#database-schema)
6. [Security Architecture](#security-architecture)
7. [Sequence Diagrams](#sequence-diagrams)
8. [Technology Stack](#technology-stack)
9. [Integration Points](#integration-points)
10. [Deployment Architecture](#deployment-architecture)
11. [Error Handling & Edge Cases](#error-handling--edge-cases)

---

## 1. Architecture Overview

### High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        EventQR System Architecture                   │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│                  │         │                  │         │                  │
│   Web Browser    │────────▶│   Web Frontend   │────────▶│  API Gateway     │
│   (Buyers/       │  HTTPS  │   (React + TS)   │  REST   │  (Express)       │
│    Business)     │◀────────│                  │◀────────│                  │
│                  │         │                  │         │                  │
└──────────────────┘         └──────────────────┘         └────────┬─────────┘
                                                                    │
                                                                    │
┌──────────────────┐                                                │
│                  │                                                │
│  Mobile Scanner  │───────────────────────────────────────────────┤
│  (React Native   │              HTTPS / REST                     │
│   Android)       │                                                │
│                  │                                                │
└──────────────────┘                                                │
                                                                    │
                             ┌──────────────────────────────────────┴─────┐
                             │                                            │
                             │         Backend Services Layer              │
                             │                                            │
                             │  ┌──────────────┐  ┌──────────────┐      │
                             │  │ Auth Service │  │Event Service │      │
                             │  └──────────────┘  └──────────────┘      │
                             │                                            │
                             │  ┌──────────────┐  ┌──────────────┐      │
                             │  │Ticket Service│  │Payment Svc   │      │
                             │  └──────────────┘  └──────────────┘      │
                             │                                            │
                             │  ┌──────────────┐  ┌──────────────┐      │
                             │  │ QR Service   │  │Email Service │      │
                             │  └──────────────┘  └──────────────┘      │
                             │                                            │
                             └──────────────────┬─────────────────────────┘
                                                │
                    ┌───────────────────────────┼───────────────────────────┐
                    │                           │                           │
                    ▼                           ▼                           ▼
          ┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
          │                  │      │                  │      │                  │
          │   PostgreSQL     │      │  Mercado Pago    │      │  Email Provider  │
          │   Database       │      │   API            │      │  (SendGrid/      │
          │                  │      │                  │      │   Postmark)      │
          └──────────────────┘      └──────────────────┘      └──────────────────┘
```

### Architecture Principles

1. **Separation of Concerns**: Clear boundaries between frontend, backend services, and external integrations
2. **Security First**: All authentication via JWT; QR codes cryptographically signed
3. **Scalability**: Stateless API design; horizontal scaling ready
4. **Resilience**: Webhook retry logic; idempotent payment processing
5. **Simplicity**: MVP focuses on core flows; no premature optimization

---

## 2. System Components

### 2.1 Web Application (Frontend)

**Technology:** React 18+ with TypeScript, Vite, Tailwind CSS

**Responsibilities:**
- User registration and authentication UI
- Event discovery and listing
- Event creation and management (business accounts)
- Ticket purchase flow
- QR ticket display and download
- Sales dashboard and reporting

**Key Features:**
- Responsive design (mobile-first)
- Real-time payment status updates
- Client-side phrase generation (optional)
- Secure token storage (localStorage with httpOnly cookie fallback)

### 2.2 Mobile Scanner Application

**Technology:** React Native (Expo/bare workflow), Android first

**Responsibilities:**
- Staff authentication
- QR code scanning (camera integration)
- Online ticket validation
- Validation history display

**Key Features:**
- Fast QR scanning with immediate feedback
- Offline-first UI with sync (future enhancement)
- Simple staff role management

### 2.3 Backend API

**Technology:** Node.js (LTS), Express 4.x, TypeScript 5.x

**Core Services:**

#### Auth Service
- User registration with 16-word phrase generation
- Login and session management
- JWT token issuance and validation
- Phrase hashing (Argon2)

#### Event Service
- CRUD operations for events
- Business account validation
- Capacity management
- Event listing with filters

#### Ticket Service
- Ticket creation upon payment confirmation
- QR generation and signing
- Ticket validation and status management
- Validation logging

#### Payment Service
- Mercado Pago integration
- Payment preference creation
- Webhook processing (idempotent)
- Payment status tracking

#### Email Service
- Transactional email delivery
- QR code attachment generation
- Template rendering
- Delivery status tracking

### 2.4 PostgreSQL Database

**Version:** PostgreSQL 14+

**Responsibilities:**
- Persistent data storage
- Transactional integrity
- User, event, ticket, and payment records
- Audit logs for validations

### 2.5 External Services

#### Mercado Pago
- Payment processing
- Checkout preference API
- Webhook notifications
- Sandbox for development

#### Email Provider (SendGrid/Postmark)
- Transactional email delivery
- Template management
- Delivery tracking

---

## 3. Data Flow Diagrams

### 3.1 High-Level Data Flow

```
┌─────────────┐
│   User      │
└──────┬──────┘
       │
       │ 1. Browse Events
       ▼
┌─────────────────┐
│  Web Frontend   │
└────────┬────────┘
         │
         │ 2. GET /events
         ▼
    ┌────────────┐
    │  Backend   │──────────▶ PostgreSQL (events table)
    │    API     │
    └────┬───────┘
         │
         │ 3. Return event list
         ▼
┌─────────────────┐
│  Web Frontend   │
└────────┬────────┘
         │
         │ 4. User clicks "Buy Ticket"
         ▼
    ┌────────────┐
    │  Backend   │──────────▶ Create Payment Preference
    │    API     │◀────────── Mercado Pago API
    └────┬───────┘
         │
         │ 5. Return checkout URL
         ▼
┌─────────────────┐
│  Web Frontend   │─────▶ Redirect to Mercado Pago Checkout
└─────────────────┘
         ▲
         │ 6. Payment Complete
         │
         │ 7. Webhook Notification
         ▼
    ┌────────────┐
    │  Backend   │──────────▶ Create ticket + QR signature
    │    API     │──────────▶ Send email with QR
    └────────────┘           Email Provider
```

### 3.2 Payment Flow Detail

```
User                Frontend            Backend             Mercado Pago         Database
 │                     │                   │                      │                 │
 │─── Buy Ticket ─────▶│                   │                      │                 │
 │                     │                   │                      │                 │
 │                     │─ POST /events/    │                      │                 │
 │                     │   :id/buy         │                      │                 │
 │                     │                   │                      │                 │
 │                     │                   │─── Create Payment ──▶│                 │
 │                     │                   │    Preference         │                 │
 │                     │                   │                      │                 │
 │                     │                   │◀── Preference ID ────│                 │
 │                     │                   │                      │                 │
 │                     │◀── Checkout URL ──│                      │                 │
 │                     │                   │                      │                 │
 │◀─── Redirect ───────│                   │                      │                 │
 │                     │                   │                      │                 │
 │─────────────── Complete Payment on MP ─────────────────────▶│                 │
 │                     │                   │                      │                 │
 │                     │                   │◀──── Webhook ────────│                 │
 │                     │                   │     (payment.         │                 │
 │                     │                   │      approved)        │                 │
 │                     │                   │                      │                 │
 │                     │                   │─── Verify Payment ───▶│                 │
 │                     │                   │                      │                 │
 │                     │                   │◀── Payment Details ──│                 │
 │                     │                   │                      │                 │
 │                     │                   │────── Create Ticket ─────────────────▶│
 │                     │                   │       + QR Signature                   │
 │                     │                   │                      │                 │
 │                     │                   │────── Send Email ────────────────────▶ │
 │                     │                   │       with QR                          │
 │                     │                   │                      │                 │
 │◀────────────────────────── Email Delivered ────────────────────────────────────│
```

### 3.3 QR Validation Flow

```
Staff Scanner       Backend API         Database            Validation Log
      │                  │                  │                     │
      │─ Scan QR ───────▶│                  │                     │
      │  Code             │                  │                     │
      │                  │                  │                     │
      │─ POST /tickets/  │                  │                     │
      │   :id/validate   │                  │                     │
      │                  │                  │                     │
      │                  │─── Fetch Ticket ─▶│                     │
      │                  │                  │                     │
      │                  │◀── Ticket Data ──│                     │
      │                  │                  │                     │
      │                  │─ Verify HMAC     │                     │
      │                  │  Signature        │                     │
      │                  │                  │                     │
      │                  │─ Check Status    │                     │
      │                  │  (not used)      │                     │
      │                  │                  │                     │
      │                  │─── Mark as Used ─▶│                     │
      │                  │                  │                     │
      │                  │─────── Log ──────────────────────────▶│
      │                  │        Validation                      │
      │                  │                  │                     │
      │◀─ Validation ────│                  │                     │
      │   Success         │                  │                     │
```

---

## 4. API Contract (OpenAPI Specification)

### OpenAPI 3.0 Schema

```yaml
openapi: 3.0.3
info:
  title: EventQR API
  description: QR-based event ticketing platform API
  version: 1.0.0
  contact:
    name: EventQR Team
servers:
  - url: http://localhost:3000/api/v1
    description: Local development
  - url: https://api.eventqr.example.com/api/v1
    description: Production

tags:
  - name: Auth
    description: Authentication and user management
  - name: Events
    description: Event management
  - name: Tickets
    description: Ticket operations
  - name: Payments
    description: Payment processing
  - name: Health
    description: System health checks

paths:
  /health:
    get:
      summary: Health check endpoint
      tags: [Health]
      responses:
        '200':
          description: Service is healthy
          content:
            application/json:
              schema:
                type: object
                properties:
                  status:
                    type: string
                    example: ok
                  timestamp:
                    type: string
                    format: date-time

  /auth/register:
    post:
      summary: Register a new user
      tags: [Auth]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                email:
                  type: string
                  format: email
                  example: user@example.com
                name:
                  type: string
                  example: John Doe
                generatePhrase:
                  type: boolean
                  description: If true, server generates 16-word phrase
                  default: true
                phrase:
                  type: string
                  description: User-provided 16-word phrase (if generatePhrase is false)
              required:
                - email
                - name
      responses:
        '201':
          description: User created successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  userId:
                    type: string
                    format: uuid
                  token:
                    type: string
                    description: JWT access token
                  phrase:
                    type: string
                    description: 16-word recovery phrase (ONLY returned once)
                    example: "abandon ability able about above absent absorb abstract absurd abuse access accident"
                  message:
                    type: string
                    example: "SAVE YOUR PHRASE - This is the only time it will be displayed"
        '400':
          description: Invalid input
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '409':
          description: Email already exists
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'

  /auth/login:
    post:
      summary: Login with email and phrase
      tags: [Auth]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                email:
                  type: string
                  format: email
                phrase:
                  type: string
                  description: 16-word recovery phrase
              required:
                - email
                - phrase
      responses:
        '200':
          description: Login successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  token:
                    type: string
                    description: JWT access token
                  userId:
                    type: string
                    format: uuid
                  isBusiness:
                    type: boolean
        '401':
          description: Invalid credentials
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'

  /auth/me:
    get:
      summary: Get current user profile
      tags: [Auth]
      security:
        - bearerAuth: []
      responses:
        '200':
          description: User profile
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        '401':
          $ref: '#/components/responses/UnauthorizedError'

  /events:
    get:
      summary: List all events
      tags: [Events]
      parameters:
        - in: query
          name: limit
          schema:
            type: integer
            default: 20
            maximum: 100
        - in: query
          name: offset
          schema:
            type: integer
            default: 0
        - in: query
          name: status
          schema:
            type: string
            enum: [upcoming, past, all]
            default: upcoming
      responses:
        '200':
          description: List of events
          content:
            application/json:
              schema:
                type: object
                properties:
                  events:
                    type: array
                    items:
                      $ref: '#/components/schemas/Event'
                  total:
                    type: integer
                  limit:
                    type: integer
                  offset:
                    type: integer

    post:
      summary: Create a new event (business accounts only)
      tags: [Events]
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                title:
                  type: string
                  example: "Summer Music Festival 2025"
                description:
                  type: string
                  example: "Annual outdoor music festival"
                startAt:
                  type: string
                  format: date-time
                  example: "2025-07-15T18:00:00Z"
                endAt:
                  type: string
                  format: date-time
                  example: "2025-07-15T23:00:00Z"
                location:
                  type: string
                  example: "Central Park, NYC"
                priceCents:
                  type: integer
                  description: Ticket price in cents
                  example: 5000
                capacity:
                  type: integer
                  example: 500
              required:
                - title
                - startAt
                - priceCents
      responses:
        '201':
          description: Event created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Event'
        '401':
          $ref: '#/components/responses/UnauthorizedError'
        '403':
          description: Business account required
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'

  /events/{id}:
    get:
      summary: Get event details
      tags: [Events]
      parameters:
        - in: path
          name: id
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Event details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Event'
        '404':
          description: Event not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'

  /events/{id}/buy:
    post:
      summary: Purchase a ticket for an event
      tags: [Events]
      parameters:
        - in: path
          name: id
          required: true
          schema:
            type: string
            format: uuid
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                buyerName:
                  type: string
                  example: "Jane Smith"
                buyerEmail:
                  type: string
                  format: email
                  example: "jane@example.com"
              required:
                - buyerName
                - buyerEmail
      responses:
        '200':
          description: Payment preference created
          content:
            application/json:
              schema:
                type: object
                properties:
                  preferenceId:
                    type: string
                    description: Mercado Pago preference ID
                  checkoutUrl:
                    type: string
                    description: URL to redirect user for payment
                    example: "https://www.mercadopago.com.ar/checkout/v1/redirect?pref_id=..."
                  ticketId:
                    type: string
                    format: uuid
                    description: Ticket ID (pending confirmation)
        '400':
          description: Invalid request or event sold out
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '404':
          description: Event not found

  /events/{id}/sales:
    get:
      summary: Get sales report for event (owner only)
      tags: [Events]
      security:
        - bearerAuth: []
      parameters:
        - in: path
          name: id
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Sales report
          content:
            application/json:
              schema:
                type: object
                properties:
                  eventId:
                    type: string
                    format: uuid
                  totalTicketsSold:
                    type: integer
                  totalRevenueCents:
                    type: integer
                  ticketsValidated:
                    type: integer
                  capacity:
                    type: integer
                  ticketsAvailable:
                    type: integer
        '401':
          $ref: '#/components/responses/UnauthorizedError'
        '403':
          description: Not event owner
        '404':
          description: Event not found

  /tickets/{id}:
    get:
      summary: Get ticket details
      tags: [Tickets]
      security:
        - bearerAuth: []
      parameters:
        - in: path
          name: id
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Ticket details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Ticket'
        '401':
          $ref: '#/components/responses/UnauthorizedError'
        '404':
          description: Ticket not found

  /tickets/{id}/qr:
    get:
      summary: Get QR code for ticket
      tags: [Tickets]
      parameters:
        - in: path
          name: id
          required: true
          schema:
            type: string
            format: uuid
        - in: query
          name: format
          schema:
            type: string
            enum: [json, png, svg]
            default: json
      responses:
        '200':
          description: QR code data or image
          content:
            application/json:
              schema:
                type: object
                properties:
                  ticketId:
                    type: string
                    format: uuid
                  qrData:
                    type: string
                    description: Base64-encoded QR payload
                  signature:
                    type: string
                    description: HMAC signature
            image/png:
              schema:
                type: string
                format: binary
            image/svg+xml:
              schema:
                type: string
        '404':
          description: Ticket not found

  /tickets/{id}/validate:
    post:
      summary: Validate a ticket (staff only)
      tags: [Tickets]
      security:
        - bearerAuth: []
      parameters:
        - in: path
          name: id
          required: true
          schema:
            type: string
            format: uuid
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                qrData:
                  type: string
                  description: Scanned QR code data
                signature:
                  type: string
                  description: QR signature
              required:
                - qrData
                - signature
      responses:
        '200':
          description: Ticket validated successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  valid:
                    type: boolean
                    example: true
                  ticket:
                    $ref: '#/components/schemas/Ticket'
                  message:
                    type: string
                    example: "Ticket validated successfully"
        '400':
          description: Invalid signature or ticket already used
          content:
            application/json:
              schema:
                type: object
                properties:
                  valid:
                    type: boolean
                    example: false
                  reason:
                    type: string
                    example: "Ticket already used"
                  usedAt:
                    type: string
                    format: date-time
        '401':
          $ref: '#/components/responses/UnauthorizedError'
        '404':
          description: Ticket not found

  /tickets/my-tickets:
    get:
      summary: Get current user's tickets
      tags: [Tickets]
      security:
        - bearerAuth: []
      responses:
        '200':
          description: List of user's tickets
          content:
            application/json:
              schema:
                type: object
                properties:
                  tickets:
                    type: array
                    items:
                      $ref: '#/components/schemas/Ticket'

  /payments/webhook:
    post:
      summary: Mercado Pago payment webhook
      tags: [Payments]
      description: Receives payment notifications from Mercado Pago
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                action:
                  type: string
                  example: "payment.updated"
                api_version:
                  type: string
                data:
                  type: object
                  properties:
                    id:
                      type: string
                      description: Payment ID
              additionalProperties: true
      responses:
        '200':
          description: Webhook processed
          content:
            application/json:
              schema:
                type: object
                properties:
                  received:
                    type: boolean
                    example: true
        '400':
          description: Invalid webhook data

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:
    User:
      type: object
      properties:
        id:
          type: string
          format: uuid
        email:
          type: string
          format: email
        name:
          type: string
        isBusiness:
          type: boolean
        createdAt:
          type: string
          format: date-time

    Event:
      type: object
      properties:
        id:
          type: string
          format: uuid
        ownerId:
          type: string
          format: uuid
        title:
          type: string
        description:
          type: string
        startAt:
          type: string
          format: date-time
        endAt:
          type: string
          format: date-time
        location:
          type: string
        priceCents:
          type: integer
        capacity:
          type: integer
        ticketsSold:
          type: integer
        createdAt:
          type: string
          format: date-time

    Ticket:
      type: object
      properties:
        id:
          type: string
          format: uuid
        eventId:
          type: string
          format: uuid
        buyerEmail:
          type: string
          format: email
        buyerName:
          type: string
        priceCents:
          type: integer
        status:
          type: string
          enum: [pending, purchased, used, refunded]
        mpPaymentId:
          type: string
        qrSignature:
          type: string
        createdAt:
          type: string
          format: date-time
        validatedAt:
          type: string
          format: date-time
          nullable: true

    Payment:
      type: object
      properties:
        id:
          type: string
          format: uuid
        ticketId:
          type: string
          format: uuid
        mpId:
          type: string
        amountCents:
          type: integer
        status:
          type: string
          enum: [pending, approved, rejected, refunded]
        createdAt:
          type: string
          format: date-time

    Error:
      type: object
      properties:
        error:
          type: string
        message:
          type: string
        code:
          type: string

  responses:
    UnauthorizedError:
      description: Access token is missing or invalid
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
```

---

## 5. Database Schema

### Complete SQL Schema

```sql
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users Table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  is_business BOOLEAN DEFAULT false,
  phrase_hash TEXT NOT NULL, -- Argon2 hash of 16-word phrase
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),

  CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$')
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_is_business ON users(is_business) WHERE is_business = true;

-- Events Table
CREATE TABLE events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT,
  start_at TIMESTAMPTZ NOT NULL,
  end_at TIMESTAMPTZ,
  location TEXT,
  price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
  capacity INTEGER CHECK (capacity > 0),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),

  CONSTRAINT valid_event_dates CHECK (end_at IS NULL OR end_at > start_at)
);

CREATE INDEX idx_events_owner ON events(owner_id);
CREATE INDEX idx_events_start_at ON events(start_at);
CREATE INDEX idx_events_upcoming ON events(start_at) WHERE start_at > now();

-- Tickets Table
CREATE TABLE tickets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  buyer_email TEXT NOT NULL,
  buyer_name TEXT NOT NULL,
  price_cents INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'purchased', 'used', 'refunded')),
  mp_payment_id TEXT, -- Mercado Pago payment ID
  qr_signature TEXT, -- HMAC signature for QR validation
  created_at TIMESTAMPTZ DEFAULT now(),
  validated_at TIMESTAMPTZ, -- When ticket was validated/scanned

  CONSTRAINT valid_buyer_email CHECK (buyer_email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$')
);

CREATE INDEX idx_tickets_event ON tickets(event_id);
CREATE INDEX idx_tickets_buyer_email ON tickets(buyer_email);
CREATE INDEX idx_tickets_mp_payment_id ON tickets(mp_payment_id);
CREATE INDEX idx_tickets_status ON tickets(status);
CREATE UNIQUE INDEX idx_tickets_mp_payment_unique ON tickets(mp_payment_id) WHERE mp_payment_id IS NOT NULL;

-- Payments Table
CREATE TABLE payments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id UUID REFERENCES tickets(id) ON DELETE SET NULL,
  mp_id TEXT UNIQUE NOT NULL, -- Mercado Pago payment ID
  amount_cents INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'refunded', 'cancelled')),
  raw_payload JSONB, -- Full webhook payload for debugging
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_payments_mp_id ON payments(mp_id);
CREATE INDEX idx_payments_ticket_id ON payments(ticket_id);
CREATE INDEX idx_payments_status ON payments(status);

-- Validation Logs Table
CREATE TABLE validation_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  staff_id UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ DEFAULT now(),
  result TEXT NOT NULL CHECK (result IN ('success', 'already_used', 'invalid_signature', 'not_found', 'refunded')),
  note TEXT,
  ip_address INET,
  user_agent TEXT
);

CREATE INDEX idx_validation_logs_ticket ON validation_logs(ticket_id);
CREATE INDEX idx_validation_logs_staff ON validation_logs(staff_id);
CREATE INDEX idx_validation_logs_validated_at ON validation_logs(validated_at);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_events_updated_at BEFORE UPDATE ON events
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_payments_updated_at BEFORE UPDATE ON payments
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- View: Event Sales Summary
CREATE VIEW event_sales_summary AS
SELECT
  e.id AS event_id,
  e.title,
  e.owner_id,
  COUNT(t.id) FILTER (WHERE t.status = 'purchased' OR t.status = 'used') AS tickets_sold,
  SUM(t.price_cents) FILTER (WHERE t.status = 'purchased' OR t.status = 'used') AS total_revenue_cents,
  COUNT(t.id) FILTER (WHERE t.status = 'used') AS tickets_validated,
  e.capacity,
  CASE
    WHEN e.capacity IS NOT NULL
    THEN e.capacity - COUNT(t.id) FILTER (WHERE t.status = 'purchased' OR t.status = 'used')
    ELSE NULL
  END AS tickets_available
FROM events e
LEFT JOIN tickets t ON e.id = t.event_id
GROUP BY e.id, e.title, e.owner_id, e.capacity;

-- Sample seed data (for development)
COMMENT ON TABLE users IS 'User accounts with phrase-based authentication';
COMMENT ON TABLE events IS 'Events created by business accounts';
COMMENT ON TABLE tickets IS 'Tickets purchased for events';
COMMENT ON TABLE payments IS 'Payment records from Mercado Pago';
COMMENT ON TABLE validation_logs IS 'Audit log of ticket validations';
```

### Database Migrations Strategy

**Migration Tool:** Use `node-pg-migrate` or `knex.js` migrations

**Migration Files:**
```
/src/backend/db/migrations/
  001_create_users_table.sql
  002_create_events_table.sql
  003_create_tickets_table.sql
  004_create_payments_table.sql
  005_create_validation_logs_table.sql
  006_create_views_and_functions.sql
```

**Seed Data:**
```sql
-- /src/backend/db/seeds/001_sample_business.sql
INSERT INTO users (email, name, is_business, phrase_hash) VALUES
('business@eventqr.com', 'EventQR Demo Business', true,
 '$argon2id$v=19$m=65536,t=3,p=4$...' -- Hash of known test phrase
);

-- Sample event for testing
INSERT INTO events (owner_id, title, description, start_at, location, price_cents, capacity)
SELECT
  id,
  'Test Concert 2025',
  'A sample event for testing',
  now() + interval '30 days',
  'Test Venue, Test City',
  2500,
  100
FROM users WHERE email = 'business@eventqr.com';
```

---

## 6. Security Architecture

### 6.1 16-Word Phrase System

**Concept:** Wallet-inspired recovery mechanism; phrase acts as master credential.

#### Generation
```javascript
// Server-side generation (MVP approach)
// Uses BIP39 wordlist for standardization
import * as bip39 from 'bip39';

function generatePhrase(): string {
  const mnemonic = bip39.generateMnemonic(128); // 12 words
  // Or use 16-word custom generator
  return mnemonic;
}
```

#### Storage & Hashing
```javascript
// Use Argon2id for phrase hashing (recommended over bcrypt for secrets)
import argon2 from 'argon2';

async function hashPhrase(phrase: string): Promise<string> {
  return await argon2.hash(phrase, {
    type: argon2.argon2id,
    memoryCost: 65536, // 64 MB
    timeCost: 3,
    parallelism: 4
  });
}

async function verifyPhrase(phrase: string, hash: string): Promise<boolean> {
  return await argon2.verify(hash, phrase);
}
```

#### Security Considerations
- **Never log or expose phrase** after initial display
- **One-time display**: Show phrase once during registration with clear UX warning
- **No server-side recovery**: Phrase is user's responsibility (wallet-style)
- **Client-side generation option** (future): Allow users to generate phrase offline
- **Encrypted backup** (optional): Offer encrypted server backup with separate password

### 6.2 QR Code Security

**Scheme:** Cryptographically signed QR codes to prevent forgery

#### QR Payload Structure
```json
{
  "ticketId": "uuid-v4",
  "mpPaymentId": "mp-payment-id",
  "signature": "hmac-sha256-hex"
}
```

#### Signature Generation
```javascript
import crypto from 'crypto';

function generateQRSignature(
  ticketId: string,
  mpPaymentId: string,
  secret: string
): string {
  const payload = `${ticketId}:${mpPaymentId}`;
  return crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
}

function verifyQRSignature(
  ticketId: string,
  mpPaymentId: string,
  signature: string,
  secret: string
): boolean {
  const expected = generateQRSignature(ticketId, mpPaymentId, secret);
  return crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expected, 'hex')
  );
}
```

#### QR Generation
```javascript
import QRCode from 'qrcode';

async function generateQRCode(ticket: Ticket): Promise<string> {
  const payload = {
    ticketId: ticket.id,
    mpPaymentId: ticket.mpPaymentId,
    signature: ticket.qrSignature
  };

  const qrData = Buffer.from(JSON.stringify(payload)).toString('base64');
  return await QRCode.toDataURL(qrData);
}
```

### 6.3 JWT Session Management

**Token Structure:**
```json
{
  "userId": "uuid",
  "email": "user@example.com",
  "isBusiness": false,
  "iat": 1699999999,
  "exp": 1700000999
}
```

**Implementation:**
```javascript
import jwt from 'jsonwebtoken';

interface TokenPayload {
  userId: string;
  email: string;
  isBusiness: boolean;
}

function generateToken(payload: TokenPayload): string {
  return jwt.sign(payload, process.env.JWT_SECRET!, {
    expiresIn: '7d',
    issuer: 'eventqr-api'
  });
}

function verifyToken(token: string): TokenPayload {
  return jwt.verify(token, process.env.JWT_SECRET!, {
    issuer: 'eventqr-api'
  }) as TokenPayload;
}
```

**Middleware:**
```javascript
import { Request, Response, NextFunction } from 'express';

async function authenticateToken(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const payload = verifyToken(token);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
```

### 6.4 Payment Security

**Principles:**
- **Never store card data**: All payment details handled by Mercado Pago
- **Server-side preference creation**: Prevent client-side price manipulation
- **Webhook validation**: Verify webhook authenticity
- **Idempotency**: Handle duplicate webhook notifications

**Webhook Validation:**
```javascript
import crypto from 'crypto';

function validateMPWebhook(
  payload: any,
  signature: string,
  secret: string
): boolean {
  // Mercado Pago uses x-signature header
  // Verify using MP's signature validation logic
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(JSON.stringify(payload))
    .digest('hex');

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}
```

**Idempotent Payment Processing:**
```javascript
async function processPaymentWebhook(mpPaymentId: string) {
  // Check if payment already processed
  const existing = await db.payments.findOne({ mp_id: mpPaymentId });
  if (existing && existing.status === 'approved') {
    console.log('Payment already processed:', mpPaymentId);
    return existing;
  }

  // Fetch payment details from MP API
  const payment = await mercadopago.payment.get(mpPaymentId);

  if (payment.status === 'approved') {
    // Create/update ticket and send email
    await createTicketAndSendEmail(payment);
  }

  // Update payment record
  await db.payments.upsert({
    mp_id: mpPaymentId,
    status: payment.status,
    raw_payload: payment
  });
}
```

### 6.5 Additional Security Measures

- **Rate Limiting**: Implement per-IP and per-user rate limits
- **CORS**: Restrict to known origins
- **HTTPS Only**: Enforce TLS in production
- **SQL Injection Prevention**: Use parameterized queries
- **XSS Prevention**: Sanitize user inputs; use Content-Security-Policy headers
- **Secrets Management**: Use environment variables; consider Vault for production

**Environment Variables:**
```bash
# .env.example
DATABASE_URL=postgresql://user:pass@localhost:5432/eventqr
JWT_SECRET=your-256-bit-secret-here-generate-with-openssl
QR_SIGNING_SECRET=another-256-bit-secret-for-qr-hmac

MERCADOPAGO_ACCESS_TOKEN=your-mp-access-token
MERCADOPAGO_PUBLIC_KEY=your-mp-public-key
MERCADOPAGO_WEBHOOK_SECRET=your-mp-webhook-secret

EMAIL_PROVIDER=sendgrid # or postmark
SENDGRID_API_KEY=your-sendgrid-key
EMAIL_FROM=noreply@eventqr.com

NODE_ENV=development
PORT=3000
```

---

## 7. Sequence Diagrams

### 7.1 User Registration Flow

```
┌──────┐          ┌─────────┐          ┌─────────┐          ┌──────────┐
│Client│          │ Web App │          │   API   │          │ Database │
└──┬───┘          └────┬────┘          └────┬────┘          └────┬─────┘
   │                   │                    │                     │
   │ Open registration │                    │                     │
   ├──────────────────▶│                    │                     │
   │                   │                    │                     │
   │ Enter email/name  │                    │                     │
   ├──────────────────▶│                    │                     │
   │                   │                    │                     │
   │                   │ POST /auth/register│                     │
   │                   ├───────────────────▶│                     │
   │                   │  {email, name,     │                     │
   │                   │   generatePhrase}  │                     │
   │                   │                    │                     │
   │                   │                    │ Generate 16-word    │
   │                   │                    │ phrase (BIP39)      │
   │                   │                    │                     │
   │                   │                    │ Hash phrase         │
   │                   │                    │ (Argon2)            │
   │                   │                    │                     │
   │                   │                    │ INSERT user         │
   │                   │                    ├────────────────────▶│
   │                   │                    │                     │
   │                   │                    │ User record created │
   │                   │                    │◀────────────────────│
   │                   │                    │                     │
   │                   │                    │ Generate JWT        │
   │                   │                    │                     │
   │                   │ {userId, token,    │                     │
   │                   │  phrase (once)}    │                     │
   │                   │◀───────────────────│                     │
   │                   │                    │                     │
   │ Display phrase    │                    │                     │
   │ with warning:     │                    │                     │
   │ "SAVE THIS -      │                    │                     │
   │  shown ONCE!"     │                    │                     │
   │◀──────────────────│                    │                     │
   │                   │                    │                     │
   │ User copies phrase│                    │                     │
   ├──────────────────▶│                    │                     │
   │                   │                    │                     │
   │ Confirm saved     │                    │                     │
   ├──────────────────▶│ Store JWT in       │                     │
   │                   │ localStorage       │                     │
   │                   │                    │                     │
   │ Redirect to       │                    │                     │
   │ dashboard         │                    │                     │
   │◀──────────────────│                    │                     │
```

### 7.2 Event Creation Flow

```
┌──────────┐     ┌─────────┐     ┌─────────┐     ┌──────────┐
│ Business │     │ Web App │     │   API   │     │ Database │
│  Owner   │     │         │     │         │     │          │
└────┬─────┘     └────┬────┘     └────┬────┘     └────┬─────┘
     │                │               │               │
     │ Click "Create  │               │               │
     │ Event"         │               │               │
     ├───────────────▶│               │               │
     │                │               │               │
     │ Fill form:     │               │               │
     │ - Title        │               │               │
     │ - Date/time    │               │               │
     │ - Location     │               │               │
     │ - Price        │               │               │
     │ - Capacity     │               │               │
     ├───────────────▶│               │               │
     │                │               │               │
     │ Submit         │ POST /events  │               │
     ├───────────────▶├──────────────▶│               │
     │                │ (with JWT)    │               │
     │                │               │               │
     │                │               │ Verify JWT    │
     │                │               │               │
     │                │               │ Check user    │
     │                │               │ is_business   │
     │                │               │               │
     │                │               │ INSERT event  │
     │                │               ├──────────────▶│
     │                │               │               │
     │                │               │ Event created │
     │                │               │◀──────────────│
     │                │               │               │
     │                │ {event}       │               │
     │                │◀──────────────│               │
     │                │               │               │
     │ Event page     │               │               │
     │ displayed with │               │               │
     │ share link     │               │               │
     │◀───────────────│               │               │
```

### 7.3 Ticket Purchase Flow (with Mercado Pago)

```
┌──────┐    ┌────────┐    ┌────────┐    ┌──────────┐    ┌──────────┐    ┌────────┐
│ Buyer│    │Web App │    │  API   │    │ Mercado  │    │ Database │    │ Email  │
│      │    │        │    │        │    │   Pago   │    │          │    │Service │
└──┬───┘    └───┬────┘    └───┬────┘    └────┬─────┘    └────┬─────┘    └───┬────┘
   │            │              │              │               │               │
   │ Browse     │              │              │               │               │
   │ events     │ GET /events  │              │               │               │
   ├───────────▶├─────────────▶│              │               │               │
   │            │              │              │               │               │
   │            │◀─────────────│              │               │               │
   │            │ Event list   │              │               │               │
   │◀───────────│              │              │               │               │
   │            │              │              │               │               │
   │ Select     │              │              │               │               │
   │ event      │              │              │               │               │
   ├───────────▶│              │              │               │               │
   │            │              │              │               │               │
   │ Click "Buy"│              │              │               │               │
   ├───────────▶│              │              │               │               │
   │            │              │              │               │               │
   │ Enter name │              │              │               │               │
   │ & email    │              │              │               │               │
   ├───────────▶│              │              │               │               │
   │            │              │              │               │               │
   │            │POST /events/ │              │               │               │
   │            │:id/buy       │              │               │               │
   │            ├─────────────▶│              │               │               │
   │            │ {buyerName,  │              │               │               │
   │            │  buyerEmail} │              │               │               │
   │            │              │              │               │               │
   │            │              │ Create       │               │               │
   │            │              │ payment      │               │               │
   │            │              │ preference   │               │               │
   │            │              ├─────────────▶│               │               │
   │            │              │              │               │               │
   │            │              │ Preference   │               │               │
   │            │              │ ID + checkout│               │               │
   │            │              │ URL          │               │               │
   │            │              │◀─────────────│               │               │
   │            │              │              │               │               │
   │            │              │ INSERT       │               │               │
   │            │              │ pending      │               │               │
   │            │              │ ticket       │               │               │
   │            │              ├──────────────┼──────────────▶│               │
   │            │              │              │               │               │
   │            │ {preferenceId│              │               │               │
   │            │  checkoutUrl}│              │               │               │
   │            │◀─────────────│              │               │               │
   │            │              │              │               │               │
   │ Redirect to│              │              │               │               │
   │ MP checkout│              │              │               │               │
   │◀───────────│              │              │               │               │
   │            │              │              │               │               │
   │            │              │              │               │               │
   │─────────── Complete Payment on MP ──────▶│               │               │
   │            │              │              │               │               │
   │            │              │              │ Payment       │               │
   │            │              │              │ approved      │               │
   │            │              │              │               │               │
   │            │              │◀─────────────┤               │               │
   │            │              │ POST         │               │               │
   │            │              │ /payments/   │               │               │
   │            │              │ webhook      │               │               │
   │            │              │              │               │               │
   │            │              │ Verify       │               │               │
   │            │              │ webhook      │               │               │
   │            │              │ signature    │               │               │
   │            │              │              │               │               │
   │            │              │ Fetch full   │               │               │
   │            │              │ payment data │               │               │
   │            │              ├─────────────▶│               │               │
   │            │              │              │               │               │
   │            │              │ Payment      │               │               │
   │            │              │ details      │               │               │
   │            │              │◀─────────────│               │               │
   │            │              │              │               │               │
   │            │              │ UPDATE ticket│               │               │
   │            │              │ status=      │               │               │
   │            │              │ 'purchased'  │               │               │
   │            │              ├──────────────┼──────────────▶│               │
   │            │              │              │               │               │
   │            │              │ Generate QR  │               │               │
   │            │              │ signature    │               │               │
   │            │              │              │               │               │
   │            │              │ UPDATE       │               │               │
   │            │              │ qr_signature │               │               │
   │            │              ├──────────────┼──────────────▶│               │
   │            │              │              │               │               │
   │            │              │ Send email   │               │               │
   │            │              │ with QR      │               │               │
   │            │              ├──────────────┼───────────────┼──────────────▶│
   │            │              │              │               │               │
   │            │              │              │               │               │ Email
   │            │              │              │               │               │ delivered
   │◀───────────────────────── Email with QR ticket ─────────────────────────┤
   │            │              │              │               │               │
```

### 7.4 QR Validation Flow

```
┌──────────┐    ┌────────┐    ┌────────┐    ┌──────────┐    ┌────────────┐
│  Staff   │    │ Mobile │    │  API   │    │ Database │    │Validation  │
│ Scanner  │    │  App   │    │        │    │          │    │    Log     │
└────┬─────┘    └───┬────┘    └───┬────┘    └────┬─────┘    └─────┬──────┘
     │              │              │              │                 │
     │ Open scanner │              │              │                 │
     │ app          │              │              │                 │
     ├─────────────▶│              │              │                 │
     │              │              │              │                 │
     │              │ Check JWT    │              │                 │
     │              │ (staff login)│              │                 │
     │              │              │              │                 │
     │ Scan QR code │              │              │                 │
     ├─────────────▶│              │              │                 │
     │              │              │              │                 │
     │              │ Parse QR data│              │                 │
     │              │ {ticketId,   │              │                 │
     │              │  mpPaymentId,│              │                 │
     │              │  signature}  │              │                 │
     │              │              │              │                 │
     │              │ POST /tickets│              │                 │
     │              │ /:id/validate│              │                 │
     │              ├─────────────▶│              │                 │
     │              │ (with JWT)   │              │                 │
     │              │              │              │                 │
     │              │              │ Verify JWT   │                 │
     │              │              │ (staff role) │                 │
     │              │              │              │                 │
     │              │              │ SELECT ticket│                 │
     │              │              ├─────────────▶│                 │
     │              │              │              │                 │
     │              │              │ Ticket data  │                 │
     │              │              │◀─────────────│                 │
     │              │              │              │                 │
     │              │              │ Verify HMAC  │                 │
     │              │              │ signature    │                 │
     │              │              │ (timing-safe)│                 │
     │              │              │              │                 │
     │              │              │ Check status │                 │
     │              │              │ != 'used'    │                 │
     │              │              │              │                 │
     │              │              │ ✓ VALID      │                 │
     │              │              │              │                 │
     │              │              │ UPDATE ticket│                 │
     │              │              │ SET status=  │                 │
     │              │              │ 'used',      │                 │
     │              │              │ validated_at │                 │
     │              │              ├─────────────▶│                 │
     │              │              │              │                 │
     │              │              │              │                 │
     │              │              │ INSERT       │                 │
     │              │              │ validation   │                 │
     │              │              │ log          │                 │
     │              │              ├─────────────────────────────────▶│
     │              │              │              │                 │
     │              │ {valid: true,│              │                 │
     │              │  ticket: {...│              │                 │
     │              │  message:    │              │                 │
     │              │  "Valid"}    │              │                 │
     │              │◀─────────────│              │                 │
     │              │              │              │                 │
     │ Show success │              │              │                 │
     │ (green ✓)    │              │              │                 │
     │◀─────────────│              │              │                 │
     │              │              │              │                 │
     │ Display      │              │              │                 │
     │ ticket info: │              │              │                 │
     │ - Buyer name │              │              │                 │
     │ - Event      │              │              │                 │
     │ - Timestamp  │              │              │                 │
     │◀─────────────│              │              │                 │
```

**Validation Error Cases:**

```
Case 1: Invalid Signature
────────────────────────
API verifies HMAC → FAIL
Response: {valid: false, reason: "Invalid signature"}
Scanner displays: RED X "Invalid Ticket"

Case 2: Already Used
────────────────────
API checks status → 'used'
Response: {valid: false, reason: "Already used", usedAt: "2025-07-15T19:30:00Z"}
Scanner displays: YELLOW ! "Ticket Already Scanned at 19:30"

Case 3: Refunded
────────────────
API checks status → 'refunded'
Response: {valid: false, reason: "Ticket refunded"}
Scanner displays: RED X "Ticket Refunded"

Case 4: Not Found
─────────────────
API queries ticket → null
Response: {valid: false, reason: "Ticket not found"}
Scanner displays: RED X "Ticket Not Found"
```

---

## 8. Technology Stack

### 8.1 Frontend (Web Application)

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Framework** | React | 18+ | UI library |
| **Language** | TypeScript | 5.x | Type safety |
| **Build Tool** | Vite | 5.x | Fast dev server & bundler |
| **Styling** | Tailwind CSS | 3.x | Utility-first CSS |
| **State Management** | React Query | 5.x | Server state caching |
| **Auth State** | Context API | - | Client auth state |
| **Routing** | React Router | 6.x | SPA routing |
| **HTTP Client** | Axios | 1.x | API requests |
| **QR Generation** | qrcode.react | 3.x | Display QR codes |
| **Forms** | React Hook Form | 7.x | Form handling |
| **Validation** | Zod | 3.x | Schema validation |

### 8.2 Mobile (Scanner Application)

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Framework** | React Native | 0.72+ | Mobile framework |
| **Language** | TypeScript | 5.x | Type safety |
| **Platform** | Android (first) | API 26+ | Target platform |
| **Camera** | react-native-camera | 4.x | QR scanning |
| **Navigation** | React Navigation | 6.x | Screen navigation |
| **State** | React Query | 5.x | API state management |

**Future:** iOS support with minimal changes

### 8.3 Backend (API)

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Runtime** | Node.js | 20 LTS | Server runtime |
| **Framework** | Express | 4.x | Web framework |
| **Language** | TypeScript | 5.x | Type safety |
| **Database** | PostgreSQL | 14+ | Relational database |
| **ORM/Query Builder** | Knex.js | 3.x | SQL query builder |
| **Auth** | jsonwebtoken | 9.x | JWT handling |
| **Password Hash** | argon2 | 0.31+ | Phrase hashing |
| **Validation** | Zod | 3.x | Request validation |
| **QR Generation** | qrcode | 1.x | Server-side QR |
| **Crypto** | Node crypto | Built-in | HMAC signing |

### 8.4 External Services

| Service | Purpose | Integration |
|---------|---------|-------------|
| **Mercado Pago** | Payment processing | SDK + Webhooks |
| **SendGrid/Postmark** | Transactional email | REST API |

### 8.5 DevOps & Tooling

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Package Manager** | pnpm | Monorepo management |
| **Testing (Unit)** | Vitest | Fast unit tests |
| **Testing (E2E)** | Playwright | End-to-end tests |
| **Linting** | ESLint | Code quality |
| **Formatting** | Prettier | Code style |
| **CI/CD** | GitHub Actions | Automated pipeline |
| **Containerization** | Docker | Deployment |
| **Hosting (Backend)** | Railway/Render | PaaS hosting |
| **Hosting (Frontend)** | Vercel/Netlify | Static hosting |

### 8.6 Development Dependencies

```json
{
  "devDependencies": {
    "@types/node": "^20.0.0",
    "@types/express": "^4.17.0",
    "@typescript-eslint/eslint-plugin": "^6.0.0",
    "@typescript-eslint/parser": "^6.0.0",
    "eslint": "^8.0.0",
    "prettier": "^3.0.0",
    "vitest": "^1.0.0",
    "tsx": "^4.0.0",
    "nodemon": "^3.0.0"
  }
}
```

---

## 9. Integration Points

### 9.1 Mercado Pago Integration

**SDK:** `mercadopago` (official Node.js SDK)

**Setup:**
```javascript
import mercadopago from 'mercadopago';

mercadopago.configure({
  access_token: process.env.MERCADOPAGO_ACCESS_TOKEN!
});
```

**Create Payment Preference:**
```javascript
interface CreatePreferenceParams {
  eventId: string;
  ticketId: string;
  buyerEmail: string;
  buyerName: string;
  priceCents: number;
}

async function createPaymentPreference(
  params: CreatePreferenceParams
): Promise<{ preferenceId: string; checkoutUrl: string }> {
  const preference = {
    items: [
      {
        title: `Ticket for Event ${params.eventId}`,
        quantity: 1,
        unit_price: params.priceCents / 100, // Convert to currency
        currency_id: 'ARS' // Argentina Pesos (adjust per region)
      }
    ],
    payer: {
      email: params.buyerEmail,
      name: params.buyerName
    },
    back_urls: {
      success: `${process.env.FRONTEND_URL}/payment/success`,
      failure: `${process.env.FRONTEND_URL}/payment/failure`,
      pending: `${process.env.FRONTEND_URL}/payment/pending`
    },
    notification_url: `${process.env.API_URL}/api/v1/payments/webhook`,
    external_reference: params.ticketId,
    auto_return: 'approved'
  };

  const response = await mercadopago.preferences.create(preference);

  return {
    preferenceId: response.body.id,
    checkoutUrl: response.body.init_point
  };
}
```

**Webhook Processing:**
```javascript
import { Router } from 'express';

const router = Router();

router.post('/payments/webhook', async (req, res) => {
  try {
    const { action, data } = req.body;

    if (action === 'payment.updated' || action === 'payment.created') {
      const paymentId = data.id;

      // Fetch full payment details
      const payment = await mercadopago.payment.get(paymentId);

      if (payment.body.status === 'approved') {
        const ticketId = payment.body.external_reference;
        await processApprovedPayment(ticketId, payment.body);
      }
    }

    res.status(200).json({ received: true });
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

async function processApprovedPayment(ticketId: string, paymentData: any) {
  // 1. Update ticket status
  await db.tickets.update(ticketId, {
    status: 'purchased',
    mp_payment_id: paymentData.id
  });

  // 2. Generate QR signature
  const signature = generateQRSignature(
    ticketId,
    paymentData.id,
    process.env.QR_SIGNING_SECRET!
  );

  await db.tickets.update(ticketId, {
    qr_signature: signature
  });

  // 3. Record payment
  await db.payments.insert({
    ticket_id: ticketId,
    mp_id: paymentData.id,
    amount_cents: paymentData.transaction_amount * 100,
    status: 'approved',
    raw_payload: paymentData
  });

  // 4. Send email with QR
  const ticket = await db.tickets.findById(ticketId);
  await sendTicketEmail(ticket);
}
```

### 9.2 Email Service Integration

**Provider Options:** SendGrid or Postmark

**SendGrid Example:**
```javascript
import sgMail from '@sendgrid/mail';

sgMail.setApiKey(process.env.SENDGRID_API_KEY!);

interface SendTicketEmailParams {
  to: string;
  toName: string;
  eventTitle: string;
  ticketId: string;
  qrCodeDataUrl: string;
}

async function sendTicketEmail(params: SendTicketEmailParams) {
  const msg = {
    to: params.to,
    from: process.env.EMAIL_FROM!,
    subject: `Your Ticket for ${params.eventTitle}`,
    html: `
      <h1>Your Ticket is Ready!</h1>
      <p>Hi ${params.toName},</p>
      <p>Your ticket for <strong>${params.eventTitle}</strong> is confirmed.</p>
      <p>Show this QR code at the event entrance:</p>
      <img src="${params.qrCodeDataUrl}" alt="QR Code" />
      <p><small>Ticket ID: ${params.ticketId}</small></p>
    `,
    attachments: [
      {
        content: params.qrCodeDataUrl.split(',')[1], // Base64 data
        filename: 'ticket-qr.png',
        type: 'image/png',
        disposition: 'attachment'
      }
    ]
  };

  await sgMail.send(msg);
}
```

**Postmark Example:**
```javascript
import postmark from 'postmark';

const client = new postmark.ServerClient(process.env.POSTMARK_API_KEY!);

async function sendTicketEmailPostmark(params: SendTicketEmailParams) {
  await client.sendEmail({
    From: process.env.EMAIL_FROM!,
    To: params.to,
    Subject: `Your Ticket for ${params.eventTitle}`,
    HtmlBody: `
      <h1>Your Ticket is Ready!</h1>
      <p>Hi ${params.toName},</p>
      <p>Your ticket for <strong>${params.eventTitle}</strong> is confirmed.</p>
      <img src="cid:qr-code" alt="QR Code" />
    `,
    Attachments: [
      {
        Name: 'ticket-qr.png',
        Content: params.qrCodeDataUrl.split(',')[1],
        ContentType: 'image/png',
        ContentID: 'cid:qr-code'
      }
    ]
  });
}
```

---

## 10. Deployment Architecture

### 10.1 Development Environment

```
┌─────────────────────────────────────────────┐
│         Developer Machine (Localhost)        │
├─────────────────────────────────────────────┤
│                                             │
│  Frontend (Vite Dev Server)                 │
│  http://localhost:5173                      │
│  ├─ React Hot Reload                        │
│  └─ Proxy API → :3000                       │
│                                             │
│  Backend (tsx watch)                        │
│  http://localhost:3000                      │
│  ├─ Express API                             │
│  └─ Auto-restart on changes                 │
│                                             │
│  PostgreSQL (Docker)                        │
│  localhost:5432                             │
│  └─ Volume: ./data/postgres                 │
│                                             │
│  Mercado Pago: Sandbox Mode                 │
│  Email: Console Logging (dev)               │
│                                             │
└─────────────────────────────────────────────┘
```

**Start Script:**
```bash
# docker-compose.dev.yml
version: '3.8'
services:
  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: eventqr_dev
      POSTGRES_USER: dev
      POSTGRES_PASSWORD: devpass
    ports:
      - "5432:5432"
    volumes:
      - ./data/postgres:/var/lib/postgresql/data

# Start all services
pnpm dev

# Starts:
# - Frontend: pnpm --filter web-app dev
# - Backend: pnpm --filter backend dev
# - DB: docker-compose -f docker-compose.dev.yml up
```

### 10.2 Production Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         Cloud Infrastructure                      │
└──────────────────────────────────────────────────────────────────┘

┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│                 │         │                 │         │                 │
│  Vercel/Netlify │         │  Railway/Render │         │   Supabase/     │
│                 │         │                 │         │   Heroku        │
│  Frontend (SPA) │────────▶│  Backend API    │────────▶│   PostgreSQL    │
│                 │  HTTPS  │  (Docker)       │  SSL    │                 │
│  CDN Cached     │         │                 │         │   Managed DB    │
│                 │         │  Auto-scaling   │         │   Backups       │
└─────────────────┘         └────────┬────────┘         └─────────────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
                    ▼                ▼                ▼
          ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
          │   Mercado    │  │   SendGrid/  │  │   Sentry     │
          │   Pago       │  │   Postmark   │  │   (Logging)  │
          │   (Prod)     │  │   (Email)    │  │              │
          └──────────────┘  └──────────────┘  └──────────────┘
```

### 10.3 CI/CD Pipeline

**GitHub Actions Workflow:**
```yaml
# .github/workflows/ci.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: pnpm/action-setup@v2
      - name: Install dependencies
        run: pnpm install
      - name: Lint
        run: pnpm lint

  test-backend:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_DB: test
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
        ports:
          - 5432:5432
    steps:
      - uses: actions/checkout@v3
      - uses: pnpm/action-setup@v2
      - name: Install dependencies
        run: pnpm install
      - name: Run backend tests
        run: pnpm --filter backend test
        env:
          DATABASE_URL: postgresql://test:test@localhost:5432/test

  test-frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: pnpm/action-setup@v2
      - name: Install dependencies
        run: pnpm install
      - name: Run frontend tests
        run: pnpm --filter web-app test

  deploy-backend:
    needs: [lint, test-backend]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Deploy to Railway
        run: |
          # Railway CLI deployment
          railway up

  deploy-frontend:
    needs: [lint, test-frontend]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Deploy to Vercel
        run: |
          # Vercel CLI deployment
          vercel --prod
```

---

## 11. Error Handling & Edge Cases

### 11.1 Payment Webhook Failures

**Scenario:** Webhook not received or processed

**Mitigation:**
- Implement webhook retry logic (exponential backoff)
- Manual payment verification endpoint for support
- Admin dashboard to view "stuck" payments

```javascript
// Manual verification endpoint
router.post('/admin/payments/verify/:mpPaymentId', async (req, res) => {
  const { mpPaymentId } = req.params;

  // Fetch from Mercado Pago
  const payment = await mercadopago.payment.get(mpPaymentId);

  // Process if approved but not in our system
  const existing = await db.payments.findByMpId(mpPaymentId);
  if (!existing && payment.body.status === 'approved') {
    await processApprovedPayment(
      payment.body.external_reference,
      payment.body
    );
    res.json({ recovered: true });
  } else {
    res.json({ recovered: false, reason: 'Already processed or not approved' });
  }
});
```

### 11.2 Email Delivery Failures

**Scenario:** Email provider down or email bounced

**Mitigation:**
- Store email status in database
- Retry queue with exponential backoff
- Admin "resend ticket" endpoint

```sql
ALTER TABLE tickets ADD COLUMN email_sent_at TIMESTAMPTZ;
ALTER TABLE tickets ADD COLUMN email_status TEXT DEFAULT 'pending';
```

### 11.3 QR Signature Verification Edge Cases

**Case 1: Signature Mismatch**
```javascript
if (!verifyQRSignature(ticketId, mpPaymentId, signature, secret)) {
  await logValidation(ticketId, staffId, 'invalid_signature');
  return res.status(400).json({
    valid: false,
    reason: 'Invalid signature - possible forgery'
  });
}
```

**Case 2: Ticket Already Used**
```javascript
if (ticket.status === 'used') {
  await logValidation(ticketId, staffId, 'already_used');
  return res.status(400).json({
    valid: false,
    reason: 'Ticket already validated',
    usedAt: ticket.validated_at
  });
}
```

**Case 3: Refunded Ticket**
```javascript
if (ticket.status === 'refunded') {
  await logValidation(ticketId, staffId, 'refunded');
  return res.status(400).json({
    valid: false,
    reason: 'Ticket has been refunded'
  });
}
```

### 11.4 Capacity Enforcement

**Race Condition:** Multiple purchases exceeding capacity

**Solution:** Database-level constraint + transaction
```sql
-- Check capacity in transaction
BEGIN;
SELECT COUNT(*) FROM tickets
WHERE event_id = $1 AND status IN ('purchased', 'used')
FOR UPDATE;

-- If count < capacity, allow purchase
INSERT INTO tickets (...) VALUES (...);
COMMIT;
```

### 11.5 Phrase Recovery

**MVP Approach:** No server-side recovery (user responsibility)

**Future Enhancement:** Encrypted backup with separate password
```javascript
// Optional encrypted backup
import crypto from 'crypto';

function encryptPhrase(phrase: string, userPassword: string): string {
  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    deriveKey(userPassword),
    iv
  );
  // ... encryption logic
  return encryptedPhrase;
}

// User can decrypt only with their password
// Server never knows plaintext phrase
```

---

## 12. Acceptance Criteria

### Phase 0 Complete When:

- [x] This document (`app_flow.md`) is complete and reviewed
- [x] API contract defines all required endpoints
- [x] Database schema is implementation-ready
- [x] Security schemes documented with code examples
- [x] Sequence diagrams cover all critical flows
- [x] Technology stack decisions are final
- [x] Integration points clearly specified

### Next Steps:

1. **UX Researcher Agent** reads this document and creates `/handoff/ux_plan.md`
2. **UI Designer Agent** produces `/handoff/ui_design.md`
3. **Testing Agent** produces `/handoff/test_strategy.md`
4. **Backend Architect** implements APIs per this spec
5. **Frontend Developer** builds UI consuming these APIs

---

## Appendix A: Quick Reference

### Environment Variables Template

```bash
# .env.example
NODE_ENV=development
PORT=3000
API_URL=http://localhost:3000
FRONTEND_URL=http://localhost:5173

DATABASE_URL=postgresql://user:pass@localhost:5432/eventqr
DATABASE_SSL=false

JWT_SECRET=your-256-bit-secret
JWT_EXPIRES_IN=7d

QR_SIGNING_SECRET=your-qr-hmac-secret

MERCADOPAGO_ACCESS_TOKEN=TEST-1234567890
MERCADOPAGO_PUBLIC_KEY=TEST-abcdef
MERCADOPAGO_WEBHOOK_SECRET=your-webhook-secret

EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=SG.xxx
EMAIL_FROM=noreply@eventqr.com

LOG_LEVEL=info
```

### Sample curl Commands

```bash
# Health check
curl http://localhost:3000/api/v1/health

# Register user
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","name":"Test User","generatePhrase":true}'

# Login
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","phrase":"word1 word2 ... word16"}'

# Create event (requires business account + JWT)
curl -X POST http://localhost:3000/api/v1/events \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title":"Test Event",
    "startAt":"2025-12-31T20:00:00Z",
    "location":"Test Venue",
    "priceCents":5000,
    "capacity":100
  }'

# Buy ticket
curl -X POST http://localhost:3000/api/v1/events/EVENT_ID/buy \
  -H "Content-Type: application/json" \
  -d '{"buyerName":"John Doe","buyerEmail":"john@example.com"}'

# Simulate webhook (for testing)
curl -X POST http://localhost:3000/api/v1/payments/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action":"payment.updated",
    "data":{"id":"MP_PAYMENT_ID"}
  }'

# Validate ticket
curl -X POST http://localhost:3000/api/v1/tickets/TICKET_ID/validate \
  -H "Authorization: Bearer STAFF_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"qrData":"base64data","signature":"hmac_signature"}'
```

---

**Document End**

*This architecture document is ready for implementation. All subsequent agents should reference this as the source of truth for EventQR's technical architecture.*
