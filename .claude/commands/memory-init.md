# Project Initialization Prompt

Please analyze our React/TypeScript project and fill in the PROJECT STRUCTURE & MEMORY BANK section of the claude.md file.

## Instructions:

1. **Examine the codebase** - Look through the project files, dependencies, and structure
2. **Fill in all bracketed sections** in the PROJECT STRUCTURE & MEMORY BANK with specific, accurate information about our project
3. **Update the claude.md file** using the information you discover

## What to analyze and document:

**Current Project Structure:**

- Main application architecture and folder organization
- Key features and functionality currently implemented
- Overall app purpose and target users

**Technology Stack:**

- Confirm actual state management solution in use
- Identify styling approach (CSS modules, styled-components, etc.)
- Document build tool and configuration
- List testing setup and tools

**Key Business Logic:**

- Core application workflows and user journeys
- Main data models and business rules
- Important algorithms or calculations

**Current Challenges & Priorities:**

- Any TODOs, FIXME comments, or known issues
- Performance bottlenecks or areas needing optimization
- Incomplete features or planned enhancements

**Component Library:**

- Reusable components and their purposes
- Design system patterns or UI conventions
- Shared utilities and hooks

**API Integration Patterns:**

- External APIs being used
- Data fetching strategies (REST, GraphQL, etc.)
- Error handling and loading state patterns

**Routing Structure:**

- Current route definitions and organization
- Protected/authenticated routes
- Navigation patterns and layout structure

**Testing Strategy:**

- Existing test files and coverage
- Testing patterns being used
- Mock strategies for external dependencies

**Deployment & Build Process:**

- Build scripts and configuration
- Environment setup (dev, staging, prod)
- CI/CD pipeline if present

## Output Format:

Update the claude.md file by replacing all the bracketed placeholder text with actual project information. Be specific and detailed - this will serve as the knowledge base for future development tasks.

If any section doesn't apply to the current project, note that clearly (e.g., "*No formal testing strategy currently implemented*") rather than leaving it blank.