# Admin UI Redesign Design

Date: 2026-06-11
Project: `won_oss_server`
Primary surface: `gateway/admin.py`
Status: Written spec awaiting user review

## Summary

This document defines a bold redesign of the inline-rendered WON Admin dashboard. The redesign keeps the existing admin capabilities and snapshot contract largely intact, but substantially improves information hierarchy, responsiveness, scanability, and operator usability.

The target outcome is an operations-console style dashboard that:

- feels modern and intentional rather than generic and cramped
- makes important live conditions visible at a glance
- treats warnings like warnings, especially slow peer-data delivery
- remains desktop-first while becoming genuinely usable on mobile
- preserves current workflows such as kick, ban, broadcast, GitHub update, password reset, and CD-key clearing

## Context

The current Admin UI is rendered inline in [gateway/admin.py](H:/Code_Projects/won_oss_server/gateway/admin.py). It is feature-complete enough for live operations, but the interface has grown into a dense multi-page monitor with limited visual hierarchy.

Recent routing diagnostics added slow peer-data delivery metrics to the routing snapshots and surfaced them in the existing UI. That made the need for a broader UI refresh more obvious: the dashboard is now carrying more operational signal, but its layout does not help the operator distinguish between headline conditions, ordinary detail, and warning states.

The redesign is intentionally scoped as a UI and interaction restructure first, not a backend rewrite.

## Evidence And Baseline Findings

The current UI was inspected through a browser validation pass using Playwright against a local mock of the Admin dashboard generated from the real inline HTML and realistic snapshot data.

Observed findings:

1. Desktop works, but the hierarchy is flat.
   - The overview page presents many cards and information blocks with similar visual weight.
   - Important operator conditions do not stand out enough from ordinary metadata.

2. Players and Rooms are functional but visually dense.
   - Tables are readable, but the pages feel crowded.
   - Slow-peer diagnostics are visible, but they read like extra columns rather than meaningful health indicators.

3. Mobile is effectively broken.
   - The page lacks a proper viewport meta tag.
   - On a phone-sized Playwright run, the page rendered as a scaled desktop layout instead of a true responsive mobile view.

4. The UI has the feel of an accumulated admin panel rather than a cohesive operations console.
   - The shell, overview cards, tables, and utilities all work, but they do not feel unified.

These findings justify a structural redesign rather than a series of small styling patches.

## Goals

- Redesign the Admin UI into a coherent operations console.
- Preserve existing admin actions and page-level capabilities.
- Improve desktop scanability for live server monitoring.
- Make slow-peer and other warning states visually obvious.
- Make the dashboard truly responsive, including mobile navigation.
- Keep implementation risk low by reusing the current snapshot and endpoint structure where practical.

## Non-Goals

- Rewriting the Admin dashboard into a separate frontend application.
- Replacing the existing API model or introducing a new backend transport architecture.
- Adding major new admin workflows unrelated to the redesign.
- Performing unrelated refactors across the gateway stack.

## Design Options Considered

### Option 1: Conservative polish

Keep the current structure and visual language, add responsiveness, and tighten spacing and typography.

Pros:

- Lowest implementation risk
- Minimal churn
- Quick delivery

Cons:

- Would not solve the deeper hierarchy and density problems
- Would likely still feel clunky

### Option 2: Balanced refresh

Preserve the current shell and page structure, but substantially improve hierarchy, cards, tables, and responsive behavior.

Pros:

- Good value for effort
- Better clarity without much structural change

Cons:

- Might still feel like a nicer version of the old UI
- Less opportunity to make the dashboard feel purpose-built

### Option 3: Bold redesign

Retain the existing capabilities and data contract, but redesign the shell, page structure, visual hierarchy, and responsive behavior into a true operations-console UI.

Pros:

- Best match for the real usability problems
- Stronger operator experience
- Better long-term foundation for future live diagnostics

Cons:

- More implementation effort
- Requires careful browser validation to avoid regressions

### Chosen option

Option 3 was selected and approved.

## Design Direction

The redesigned Admin UI will feel like a focused network/game operations console rather than a generic admin page.

Core direction:

- dark, technical, modern, and serious
- strong distinction between health summary, live activity, and deep detail
- progressive disclosure for dense technical data
- operator-first layout, not marketing-style dashboard design

The tone should avoid both glossy SaaS styling and retro terminal cosplay.

## Information Architecture

### Global shell

The shell becomes a clearer application frame with:

- a stronger desktop sidebar
- a real mobile drawer
- a top status bar with page title and live meta
- more deliberate section spacing and surface layering

Desktop behavior:

- persistent left navigation
- stronger active state and badge presentation
- clearer visual grouping between navigation, status footer, and main content

Mobile behavior:

- proper viewport support
- collapsible navigation drawer instead of hidden desktop assumptions
- stacked layout for cards and denser content regions

### Overview

The Overview page becomes the operational command surface.

Structure:

1. Operations summary band
   - players online
   - players in game
   - live games
   - reconnects
   - active rooms
   - slow-delivery warning summary
   - update status when relevant

2. Product/runtime status
   - clear separation between Homeworld and Cataclysm runtime state
   - directory roots, routing/backend details, supported versions, and live counts

3. Utility and maintenance zone
   - server info
   - activity counters
   - GitHub update controls
   - banned IPs

The top of the page should tell the operator what deserves attention before they read any dense detail.

### Players

The Players page becomes a scan-first roster view.

Primary table emphasis:

- player identity
- state: lobby or game
- room
- connection health
- recent activity
- operator actions

Slow-peer data should remain visible, but in compact health form rather than as a purely mechanical metric column.

Expanded detail areas remain available for:

- peer-data totals
- slow-peer counters
- subscription detail
- last activity kind
- other routing diagnostics already present in the snapshot

### Rooms

The Rooms page becomes a room-health view rather than an info dump.

Each room card should immediately show:

- room name and port
- lobby/game state
- player count
- live games
- whether transport warnings exist

Deeper room content should then show:

- room metadata
- routing and peer-data counters
- slow-peer diagnostics
- player roster
- live game objects

Game rooms with degraded transport conditions should be easier to spot than quiet lobby rooms.

### Other pages

The following pages remain in scope but are not expanded functionally:

- Activity
- IP Metrics
- Database
- Sessions
- Logs

These pages should inherit the redesigned shell and visual language so the interface feels consistent, but this redesign does not add new workflows to them.

## Visual Language

### Typography

- Use a stronger display style for page titles, section headers, and key metrics.
- Use a monospace face for ports, IPs, IDs, byte values, sequence-like values, and technical payload indicators.
- Increase contrast between labels, values, and meta text.

### Color system

Base surfaces:

- layered dark graphite and slate rather than flat black everywhere

Meaning colors:

- blue/cyan for active/live state
- green for healthy
- amber for warning
- red for danger or destructive actions

Slow-peer diagnostics should visually align with warning semantics.

### Spacing and surfaces

- More breathing room between major sections
- More intentional card grouping
- Tighter density only inside tabular or technical regions
- Stronger section headers and boundaries to reduce cognitive load

### Tables

Tables should remain compact, but feel more operator-friendly through:

- clearer headers
- more consistent numeric alignment
- improved hover and reading rhythm
- stronger treatment for warning states in rows or cells where appropriate

## Interaction Model

The redesign remains mostly presentational and structural.

Preserved actions:

- kick player
- ban IP
- unban IP
- send broadcast
- check GitHub
- update from GitHub
- reset password
- clear CD key
- delete user

Interaction improvements:

- mobile navigation drawer
- clearer summary-to-detail flow
- stronger visual escalation for warnings
- more intentional expansion points for dense data

No new transport or streaming model is introduced in this redesign.

## Data Contract And Backend Boundaries

Implementation should prefer reusing the current snapshot shape already exposed through the gateway and routing manager.

Allowed changes:

- very small snapshot additions only if browser validation reveals a genuine presentation gap
- light helper extraction inside the inline HTML/JS if that improves clarity

Avoid:

- reshaping the admin API unnecessarily
- coupling the redesign to unrelated backend refactors
- turning this pass into a frontend framework migration

## Error And Edge States

The redesign must improve how edge conditions are presented.

Key states:

- no live players
- no routing rooms
- no live game objects
- empty activity/logs/database tables
- update available from GitHub
- slow-peer warnings
- readiness or auth-key issues

These states should look intentional and readable, not like missing content.

## Implementation Plan Boundaries

Expected implementation focus:

- `gateway/admin.py` shell and styling redesign
- page renderer hierarchy updates
- responsive behavior fixes
- continued surfacing of slow-peer diagnostics in a more usable form

Likely untouched or lightly touched:

- core backend routing logic
- admin action endpoints
- broader gateway architecture

## Validation Plan

Browser validation is required after implementation.

Validation flow:

1. Load the Admin dashboard in a desktop viewport.
2. Verify page identity and that the UI is not blank.
3. Check console health and ensure no framework/runtime overlay appears.
4. Validate Overview layout and information hierarchy.
5. Validate Players scanability and at least one interaction.
6. Validate Rooms scanability and at least one interaction.
7. Validate a real mobile viewport with proper responsive behavior.

Required evidence:

- desktop screenshots
- mobile screenshot
- console health report
- interaction proof for at least one key surface

Regression tests:

- update or add lightweight HTML-oriented tests where they provide value
- do not rely on unit tests alone as proof for the redesign

## Acceptance Criteria

The redesign is successful when:

1. The Admin UI feels substantially more modern and intentional.
2. The most important live server conditions are understandable at a glance.
3. Mobile renders as a real responsive UI rather than a scaled desktop page.
4. Slow-peer diagnostics are easier to spot and interpret.
5. Existing admin actions remain available and easy to reach.
6. Browser validation confirms the new UI works on both desktop and mobile.

## Risks

- Because the UI is inline-rendered, large styling and structure changes can make `gateway/admin.py` harder to maintain if not kept organized.
- A bold redesign can accidentally harm density or operator speed if style wins over scanability.
- Responsive improvements may surface table-layout tradeoffs that need deliberate treatment rather than naive stacking.

These risks are acceptable, but they should guide implementation choices.

## Recommendation

Proceed with a bold UI redesign centered on `gateway/admin.py`, while keeping the existing admin capability set and snapshot model stable.

The implementation should prioritize:

1. real responsive behavior
2. stronger overview hierarchy
3. more readable Players and Rooms pages
4. clearer warning-state treatment
5. Playwright-based browser validation before claiming success
