# Hearth Auth-Chain PoC — Postman Test Suite

> **Standalone testing guide.** Import the collection JSON, configure variables, and run folders 00–12 in order to validate every auth and policy boundary in the system.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Import the Collection](#2-import-the-collection)
3. [Collection Variables](#3-collection-variables)
4. [Execution Order](#4-execution-order)
5. [Folder-by-Folder Test Payloads](#5-folder-by-folder-test-payloads)
   - [00 — Health & JWKS](#00--health--jwks)
   - [01 — Login](#01--login)
   - [02 — User Management](#02--user-management)
   - [03 — Resident & Guest Login](#03--resident--guest-login)
   - [04 — Token Lifecycle](#04--token-lifecycle)
   - [05 — NAS Own Workspace](#05--nas-own-workspace)
   - [06 — NAS Shared Workspace](#06--nas-shared-workspace)
   - [07 — Workspace Lifecycle](#07--workspace-lifecycle)
   - [08 — Video Upload](#08--video-upload)
   - [09 — Streaming](#09--streaming)
   - [10 — Element Registry](#10--element-registry)
   - [11 — Service OAuth (`client_credentials`)](#11--service-oauth-client_credentials)
   - [12 — Policy Boundary Checks](#12--policy-boundary-checks)
6. [Assertions Summary](#6-assertions-summary)
7. [Newman CLI](#7-newman-cli)

---

## 1. Prerequisites

| Requirement | Notes |
|---|---|
| **Docker stack running** | `docker compose up -d` from project root |
| **Postman ≥ v10** | [Download](https://www.postman.com/downloads/) or use Newman for CLI |
| **Collection JSON** | `postman/Hearth-AuthChain-Postman.json` (in this repo) |
| **Gateway reachable** | `https://localhost:8443` (TLS — disable SSL verification in Postman settings) |
| **Management port** | `http://localhost:8081` (health, JWKS — HTTP, no TLS) |

> [!IMPORTANT]
> The API Gateway uses self-signed TLS on port **8443**. In Postman → **Settings → General → SSL certificate verification → OFF** before running any request.

---

## 2. Import the Collection

1. Open Postman → click **Import** (top-left).
2. Choose **File** tab → select `postman/Hearth-AuthChain-Postman.json`.
3. Click **Import**. You will see a collection named **"Hearth AuthChain PoC"** with 13 folders (00–12).
4. The collection ships with pre-request scripts that automatically capture tokens — no manual copy-paste needed once you set variables (see §3).

---

## 3. Collection Variables

Go to the collection → **Variables** tab and set these before your first run:

| Variable | Initial Value | Description |
|---|---|---|
| `base_url` | `https://localhost:8443` | API Gateway TLS endpoint |
| `mgmt_url` | `http://localhost:8081` | Gateway management port (health, JWKS) |
| `owner_username` | `hearth_owner` | Pre-seeded OWNER account |
| `owner_password` | `ChangeMe123!` | OWNER password (from `02-seed-auth.sql`) |
| `resident_username` | `resident01` | Created in folder 02 |
| `resident_password` | `Resident@123` | Created in folder 02 |
| `guest_username` | `guest01` | Created in folder 02 |
| `guest_password` | `Guest@123` | Created in folder 02 |
| `owner_token` | *(auto-set by script)* | Captured from folder 01 login |
| `resident_token` | *(auto-set by script)* | Captured from folder 03 login |
| `guest_token` | *(auto-set by script)* | Captured from folder 03 login |
| `refresh_token` | *(auto-set by script)* | Captured from folder 01 login |
| `session_id` | *(auto-set by script)* | Captured from JWT `sid` claim |
| `element_id` | `elem-living-room-01` | Any valid element ID in your registry seed |
| `VIDEO_SVC_CLIENT_ID` | `video-service` | From `service_clients` seed |
| `VIDEO_SVC_SECRET` | `video-svc-secret-change-me` | Plaintext secret from `02-seed-auth.sql` |
| `upload_file_path` | `/tmp/test-video.mp4` | Absolute path to a local MP4 for upload test |

> [!TIP]
> You can also set `owner_token`, `resident_token`, `guest_token` manually by running folder 01 and 03 first, then copy tokens from the response bodies into the variables panel.

---

## 4. Execution Order

Run folders **strictly in this order** — later folders depend on tokens and IDs captured by earlier ones.

```
00  Health & JWKS          ← sanity check: stack is up
01  Login                  ← captures owner_token, refresh_token, session_id
02  User Management        ← creates resident01, guest01
03  Resident & Guest Login ← captures resident_token, guest_token
04  Token Lifecycle        ← refresh, reuse-attack, logout, re-login
05  NAS Own Workspace      ← list, mkdir, upload, download, delete
06  NAS Shared Workspace   ← shared reads/writes, role boundaries
07  Workspace Lifecycle    ← create, clear, delete workspace
08  Video Upload           ← resident ✅, guest ❌
09  Streaming              ← stream root, HLS playlist/segment (public token)
10  Element Registry       ← read, control, guest-forbidden
11  Service OAuth          ← client_credentials (JSON + form), wrong secret
12  Policy Boundary        ← expired JWT, wrong method, cross-user snooping
```

---

## 5. Folder-by-Folder Test Payloads

---

### 00 — Health & JWKS

**Purpose:** Confirm all services are reachable before running any auth tests.

#### 00.1 Gateway Health
```
GET http://localhost:8081/internal/health
```
**Expected:** `200 OK`
```json
{ "status": "UP" }
```

#### 00.2 JWKS Endpoint
```
GET http://localhost:8081/internal/jwks
```
**Expected:** `200 OK`
```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "use": "sig",
      "kid": "gateway-sig-v1",
      "x": "...",
      "y": "..."
    }
  ]
}
```

#### 00.3 Auth-Service Health (through Gateway)
```
GET https://localhost:8443/api/v1/auth/actuator/health
```
**Expected:** `200 OK` — confirms gateway routing to auth-service works.

---

### 01 — Login

**Purpose:** Obtain OWNER tokens. Pre-request script captures `owner_token`, `refresh_token`, `session_id`.

#### 01.1 Happy Path — OWNER Login ✅
```
POST https://localhost:8443/api/v1/auth/login
Content-Type: application/json

{
  "username": "{{owner_username}}",
  "password": "{{owner_password}}",
  "deviceId": "postman-dev-001"
}
```
**Expected:** `200 OK`
```json
{
  "accessToken": "<JWT>",
  "refreshToken": "<opaque-43-char-string>",
  "expiresIn": 900
}
```
**Post-response script saves:**
```js
pm.collectionVariables.set("owner_token", pm.response.json().accessToken);
pm.collectionVariables.set("refresh_token", pm.response.json().refreshToken);
// decode JWT to extract sid claim for session_id
const payload = JSON.parse(atob(pm.response.json().accessToken.split('.')[1]));
pm.collectionVariables.set("session_id", payload.sid);
```

#### 01.2 Wrong Password ❌
```
POST https://localhost:8443/api/v1/auth/login
Content-Type: application/json

{
  "username": "{{owner_username}}",
  "password": "WrongPassword!"
}
```
**Expected:** `401 Unauthorized`
```json
{ "error": "INVALID_CREDENTIALS", "message": "Bad username or password" }
```

#### 01.3 Missing Password Field ❌
```
POST https://localhost:8443/api/v1/auth/login
Content-Type: application/json

{
  "username": "{{owner_username}}"
}
```
**Expected:** `400 Bad Request`

#### 01.4 Non-Existent User ❌
```
POST https://localhost:8443/api/v1/auth/login
Content-Type: application/json

{
  "username": "nobody",
  "password": "DoesNotMatter1!"
}
```
**Expected:** `401 Unauthorized`

---

### 02 — User Management

**Purpose:** OWNER creates RESIDENT and GUEST accounts. Tests authorization boundaries (non-OWNER forbidden).

> [!NOTE]
> All requests in this folder use `Authorization: Bearer {{owner_token}}`.

#### 02.1 Create RESIDENT User ✅
```
POST https://localhost:8443/api/v1/auth/users
Authorization: Bearer {{owner_token}}
Content-Type: application/json

{
  "username": "resident01",
  "password": "Resident@123",
  "role": "RESIDENT"
}
```
**Expected:** `201 Created`
```json
{
  "id": "<uuid>",
  "username": "resident01",
  "role": "RESIDENT",
  "mustChangePassword": false
}
```

#### 02.2 Create GUEST User ✅
```
POST https://localhost:8443/api/v1/auth/users
Authorization: Bearer {{owner_token}}
Content-Type: application/json

{
  "username": "guest01",
  "password": "Guest@123",
  "role": "GUEST",
  "expiresAt": "2027-12-31T23:59:59Z"
}
```
**Expected:** `201 Created`

#### 02.3 Create OWNER — Forbidden ❌
```
POST https://localhost:8443/api/v1/auth/users
Authorization: Bearer {{owner_token}}
Content-Type: application/json

{
  "username": "evil_owner",
  "password": "Evil@123",
  "role": "OWNER"
}
```
**Expected:** `403 Forbidden` — policy prevents creating a second OWNER via API.

#### 02.4 No Token — Unauthorized ❌
```
POST https://localhost:8443/api/v1/auth/users
Content-Type: application/json

{
  "username": "sneaky",
  "password": "Sneaky@123",
  "role": "RESIDENT"
}
```
**Expected:** `401 Unauthorized`

#### 02.5 List Users ✅
```
GET https://localhost:8443/api/v1/auth/users
Authorization: Bearer {{owner_token}}
```
**Expected:** `200 OK` — array containing at minimum `hearth_owner`, `resident01`, `guest01`.

#### 02.6 Duplicate Username ❌
```
POST https://localhost:8443/api/v1/auth/users
Authorization: Bearer {{owner_token}}
Content-Type: application/json

{
  "username": "resident01",
  "password": "Resident@456",
  "role": "RESIDENT"
}
```
**Expected:** `409 Conflict`

---

### 03 — Resident & Guest Login

**Purpose:** Log in as RESIDENT and GUEST; capture their tokens.

#### 03.1 Resident Login ✅
```
POST https://localhost:8443/api/v1/auth/login
Content-Type: application/json

{
  "username": "{{resident_username}}",
  "password": "{{resident_password}}",
  "deviceId": "postman-dev-002"
}
```
**Expected:** `200 OK`  
**Post-response script:** `pm.collectionVariables.set("resident_token", pm.response.json().accessToken);`

#### 03.2 Guest Login ✅
```
POST https://localhost:8443/api/v1/auth/login
Content-Type: application/json

{
  "username": "{{guest_username}}",
  "password": "{{guest_password}}",
  "deviceId": "postman-dev-003"
}
```
**Expected:** `200 OK`  
**Post-response script:** `pm.collectionVariables.set("guest_token", pm.response.json().accessToken);`

---

### 04 — Token Lifecycle

**Purpose:** Validate refresh rotation, refresh-token reuse attack detection, and logout.

#### 04.1 Refresh Token — Success ✅
```
POST https://localhost:8443/api/v1/auth/refresh
Content-Type: application/json

{
  "refreshToken": "{{refresh_token}}"
}
```
**Expected:** `200 OK` — new `accessToken` + new `refreshToken`.  
**Post-response script:** Overwrite `refresh_token` with the new one.

#### 04.2 Reuse Old Refresh Token — Attack Detected ❌
Send the **same old** refresh token (before updating `{{refresh_token}}`):
```
POST https://localhost:8443/api/v1/auth/refresh
Content-Type: application/json

{
  "refreshToken": "<the-token-from-04.1-request-body>"
}
```
**Expected:** `401 Unauthorized` — refresh token already rotated; reuse invalidates entire session.

#### 04.3 Logout ✅
```
POST https://localhost:8443/api/v1/auth/logout
Authorization: Bearer {{owner_token}}
X-Session-Id: {{session_id}}
```
**Expected:** `204 No Content`

#### 04.4 Use Revoked Access Token ❌
```
GET https://localhost:8443/api/v1/nas/files/list
Authorization: Bearer {{owner_token}}
```
**Expected:** `401 Unauthorized` — token was invalidated by logout.

#### 04.5 Re-Login After Logout ✅
```
POST https://localhost:8443/api/v1/auth/login
Content-Type: application/json

{
  "username": "{{owner_username}}",
  "password": "{{owner_password}}"
}
```
**Expected:** `200 OK` — fresh token pair.  
**Post-response script:** Recapture `owner_token`, `refresh_token`, `session_id`.

---

### 05 — NAS Own Workspace

**Purpose:** RESIDENT/OWNER performs full CRUD on their own private NAS files. Guest access is blocked.

#### 05.1 List Own Workspace Files ✅
```
GET https://localhost:8443/api/v1/nas/files/list
Authorization: Bearer {{resident_token}}
```
**Expected:** `200 OK`

#### 05.2 Create Directory ✅
```
POST https://localhost:8443/api/v1/nas/files/mkdir
Authorization: Bearer {{resident_token}}
Content-Type: application/json

{
  "path": "documents/reports"
}
```
**Expected:** `200 OK` or `201 Created`

#### 05.3 Upload File ✅
```
POST https://localhost:8443/api/v1/nas/files/upload/file
Authorization: Bearer {{resident_token}}
Content-Type: multipart/form-data

file: <binary>
path: documents/reports/report.txt
```
**Expected:** `200 OK`

#### 05.4 Download File ✅
```
GET https://localhost:8443/api/v1/nas/files/download?path=documents/reports/report.txt
Authorization: Bearer {{resident_token}}
```
**Expected:** `200 OK`

#### 05.5 Preview File ✅
```
GET https://localhost:8443/api/v1/nas/files/preview?path=documents/reports/report.txt
Authorization: Bearer {{resident_token}}
```
**Expected:** `200 OK`

#### 05.6 Delete File ✅
```
DELETE https://localhost:8443/api/v1/nas/files/delete
Authorization: Bearer {{resident_token}}
Content-Type: application/json

{
  "path": "documents/reports/report.txt"
}
```
**Expected:** `200 OK` or `204 No Content`

#### 05.7 Guest Access to Private Files — Forbidden ❌
```
GET https://localhost:8443/api/v1/nas/files/list
Authorization: Bearer {{guest_token}}
```
**Expected:** `403 Forbidden` — GUEST cannot access private files.

---

### 06 — NAS Shared Workspace

**Purpose:** Validate role-based access on the `/shared` path.

| Role | List/Read | Write/Upload | Delete |
|---|---|---|---|
| OWNER | ✅ | ✅ | ✅ |
| RESIDENT | ✅ | ✅ | ✅ |
| GUEST | ✅ | ❌ | ❌ |

#### 06.1 Resident Reads Shared ✅
```
GET https://localhost:8443/api/v1/nas/shared/list
Authorization: Bearer {{resident_token}}
```
**Expected:** `200 OK`

#### 06.2 Resident Uploads to Shared ✅
```
POST https://localhost:8443/api/v1/nas/shared/upload/file
Authorization: Bearer {{resident_token}}
Content-Type: multipart/form-data

file: <any file>
path: shared-doc.txt
```
**Expected:** `200 OK`

#### 06.3 Guest Reads Shared ✅
```
GET https://localhost:8443/api/v1/nas/shared/list
Authorization: Bearer {{guest_token}}
```
**Expected:** `200 OK` — read-only access granted.

#### 06.4 Guest Writes to Shared — Forbidden ❌
```
POST https://localhost:8443/api/v1/nas/shared/upload/file
Authorization: Bearer {{guest_token}}
Content-Type: multipart/form-data

file: <any file>
path: evil-guest-upload.txt
```
**Expected:** `403 Forbidden`

#### 06.5 Owner Clears Shared ✅
```
DELETE https://localhost:8443/api/v1/nas/shared/clear
Authorization: Bearer {{owner_token}}
```
**Expected:** `200 OK` or `204 No Content`

---

### 07 — Workspace Lifecycle

**Purpose:** Create, clear, and delete a workspace. Only OWNER can delete; RESIDENT can only clear their own.

#### 07.1 Create Workspace ✅
```
POST https://localhost:8443/api/v1/nas/workspace/create
Authorization: Bearer {{owner_token}}
Content-Type: application/json

{
  "name": "test-workspace-alpha"
}
```
**Expected:** `200 OK` or `201 Created`

#### 07.2 Clear Workspace (RESIDENT) ✅
```
DELETE https://localhost:8443/api/v1/nas/workspace/clear
Authorization: Bearer {{resident_token}}
Content-Type: application/json

{
  "workspaceId": "resident01"
}
```
**Expected:** `200 OK` or `204 No Content`

#### 07.3 Delete Workspace (OWNER) ✅
```
DELETE https://localhost:8443/api/v1/nas/workspace/delete
Authorization: Bearer {{owner_token}}
Content-Type: application/json

{
  "workspaceId": "test-workspace-alpha"
}
```
**Expected:** `200 OK` or `204 No Content`

#### 07.4 RESIDENT Deletes Workspace — Forbidden ❌
```
DELETE https://localhost:8443/api/v1/nas/workspace/delete
Authorization: Bearer {{resident_token}}
Content-Type: application/json

{
  "workspaceId": "resident01"
}
```
**Expected:** `403 Forbidden` — only OWNER can permanently delete.

---

### 08 — Video Upload

**Purpose:** RESIDENT can upload video; GUEST cannot.

#### 08.1 Resident Uploads Video ✅
```
POST https://localhost:8443/api/v1/videos/upload
Authorization: Bearer {{resident_token}}
Content-Type: multipart/form-data

file: <MP4 file — set via {{upload_file_path}}>
title: My Test Video
description: Uploaded by resident01
```
**Expected:** `200 OK` or `202 Accepted`

#### 08.2 Guest Uploads Video — Forbidden ❌
```
POST https://localhost:8443/api/v1/videos/upload
Authorization: Bearer {{guest_token}}
Content-Type: multipart/form-data

file: <any file>
title: Sneaky Guest Upload
```
**Expected:** `403 Forbidden`

---

### 09 — Streaming

**Purpose:** Validate streaming endpoints — authenticated for streaming metadata, public (token-query-param) for HLS playlists/segments.

#### 09.1 Get Streaming Root (RESIDENT) ✅
```
GET https://localhost:8443/api/v1/stream?path=movies
Authorization: Bearer {{resident_token}}
```
**Expected:** `200 OK`

#### 09.2 List Playlists (RESIDENT) ✅
```
GET https://localhost:8443/api/v1/stream/playlists
Authorization: Bearer {{resident_token}}
```
**Expected:** `200 OK`

#### 09.3 Public HLS Playlist (token= param) ✅
HLS players cannot set headers — the gateway accepts a `?token=` query parameter for these routes:
```
GET https://localhost:8443/api/v1/nas/stream/playlist?token={{resident_token}}&path=movies%2Fsample.m3u8
```
No `Authorization` header.  
**Expected:** `200 OK`

#### 09.4 Public HLS Segment ✅
```
GET https://localhost:8443/api/v1/nas/stream/segment?token={{resident_token}}&path=movies%2Fsegment0.ts
```
**Expected:** `200 OK`

#### 09.5 HLS Without Token — Unauthorized ❌
```
GET https://localhost:8443/api/v1/nas/stream/playlist?path=movies%2Fsample.m3u8
```
No `Authorization` header, no `?token=` param.  
**Expected:** `401 Unauthorized`

---

### 10 — Element Registry

**Purpose:** RESIDENT can read and control elements; GUEST can only read.

#### 10.1 Read Element State (RESIDENT) ✅
```
GET https://localhost:8443/api/v1/elements/{{element_id}}
Authorization: Bearer {{resident_token}}
```
**Expected:** `200 OK`

#### 10.2 Control Element State (RESIDENT) ✅
```
PUT https://localhost:8443/api/v1/elements/{{element_id}}/state
Authorization: Bearer {{resident_token}}
Content-Type: application/json

{
  "state": "ON"
}
```
**Expected:** `200 OK`

#### 10.3 Guest Controls Element — Forbidden ❌
```
PUT https://localhost:8443/api/v1/elements/{{element_id}}/state
Authorization: Bearer {{guest_token}}
Content-Type: application/json

{
  "state": "OFF"
}
```
**Expected:** `403 Forbidden` — GUEST is read-only.

#### 10.4 Guest Reads Element ✅
```
GET https://localhost:8443/api/v1/elements/{{element_id}}
Authorization: Bearer {{guest_token}}
```
**Expected:** `200 OK` — read access is allowed.

---

### 11 — Service OAuth (`client_credentials`)

**Purpose:** Machine-to-machine auth for internal services (e.g., video-service calling auth-service).

> [!NOTE]
> These requests target the auth-service **through the gateway** at `/api/v1/auth/oauth/token`.

#### 11.1 Client Credentials — JSON Body ✅
```
POST https://localhost:8443/api/v1/auth/oauth/token
Content-Type: application/json

{
  "grant_type": "client_credentials",
  "client_id": "{{VIDEO_SVC_CLIENT_ID}}",
  "client_secret": "{{VIDEO_SVC_SECRET}}",
  "scope": "service:internal"
}
```
**Expected:** `200 OK`
```json
{
  "access_token": "<service-JWT>",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "service:internal"
}
```

#### 11.2 Client Credentials — Form-Urlencoded ✅
```
POST https://localhost:8443/api/v1/auth/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id={{VIDEO_SVC_CLIENT_ID}}
&client_secret={{VIDEO_SVC_SECRET}}
&scope=service%3Ainternal
```
**Expected:** `200 OK` — same response shape as 11.1.

#### 11.3 Wrong Client Secret ❌
```
POST https://localhost:8443/api/v1/auth/oauth/token
Content-Type: application/json

{
  "grant_type": "client_credentials",
  "client_id": "{{VIDEO_SVC_CLIENT_ID}}",
  "client_secret": "completely-wrong-secret",
  "scope": "service:internal"
}
```
**Expected:** `401 Unauthorized`
```json
{ "error": "invalid_client", "error_description": "Bad client credentials" }
```

#### 11.4 Scope Escalation Attempt ❌
```
POST https://localhost:8443/api/v1/auth/oauth/token
Content-Type: application/json

{
  "grant_type": "client_credentials",
  "client_id": "{{VIDEO_SVC_CLIENT_ID}}",
  "client_secret": "{{VIDEO_SVC_SECRET}}",
  "scope": "service:admin OWNER"
}
```
**Expected:** `400 Bad Request` or `403 Forbidden` — scope not permitted for this client.

---

### 12 — Policy Boundary Checks

**Purpose:** Validate that the gateway's policy registry rejects invalid or spoofed requests at the perimeter.

#### 12.1 Expired JWT ❌
Craft or use a manually-expired token (or wait for a short-lived token to expire):
```
GET https://localhost:8443/api/v1/nas/files/list
Authorization: Bearer <expired-JWT-here>
```
**Expected:** `401 Unauthorized`
```json
{ "error": "TOKEN_EXPIRED", "message": "JWT has expired" }
```

#### 12.2 Wrong HTTP Method ❌
The login endpoint only accepts POST:
```
GET https://localhost:8443/api/v1/auth/login
Content-Type: application/json
```
**Expected:** `405 Method Not Allowed`

#### 12.3 Cross-User Snooping — Resident Accesses Owner Files ❌
```
GET https://localhost:8443/api/v1/nas/files/list?workspace=hearth_owner
Authorization: Bearer {{resident_token}}
```
**Expected:** `403 Forbidden` — resident can only access their own workspace, not `hearth_owner`'s.

#### 12.4 Tampered JWT ❌
Take the `owner_token` and flip one character in the signature segment (last `.` section):
```
GET https://localhost:8443/api/v1/nas/files/list
Authorization: Bearer <tampered-JWT>
```
**Expected:** `401 Unauthorized` — signature validation fails.

#### 12.5 Missing Bearer Scheme ❌
```
GET https://localhost:8443/api/v1/nas/files/list
Authorization: {{owner_token}}
```
(No `Bearer ` prefix)  
**Expected:** `401 Unauthorized`

#### 12.6 Route Not Defined — 404 from Gateway ❌
```
GET https://localhost:8443/api/v1/nonexistent-service/data
Authorization: Bearer {{owner_token}}
```
**Expected:** `404 Not Found` from the gateway (no matching route).

---

## 6. Assertions Summary

| Folder | What It Validates | Key Assertions |
|---|---|---|
| **00** | Stack is up | `status == UP`, JWKS keys present |
| **01** | Login happy path + rejection | `200` with token, `401` wrong pw, `400` missing fields |
| **02** | OWNER-only user creation | `201` create, `403` create OWNER, `401` no token, `409` duplicate |
| **03** | Multi-role login | `200` for RESIDENT + GUEST, tokens captured |
| **04** | Token rotation + revocation | New token on refresh, `401` on reuse, `401` after logout |
| **05** | Private NAS CRUD | Full CRUD `200`/`201`/`204`, `403` guest, `401` unauth |
| **06** | Shared NAS role matrix | GUEST read ✅, GUEST write ❌ `403` |
| **07** | Workspace lifecycle | Create `201`, clear `204`, delete OWNER-only `403` for resident |
| **08** | Video upload authorization | RESIDENT `202`, GUEST `403` |
| **09** | HLS streaming | Authenticated root `200`, public `?token=` segments `200`, no-token `401` |
| **10** | Element registry RBAC | RESIDENT control ✅, GUEST control `403`, GUEST read ✅ |
| **11** | M2M OAuth2 | JSON + form both `200`, wrong secret `401`, scope escalation `400`/`403` |
| **12** | Perimeter security | Expired JWT `401`, tampered JWT `401`, wrong method `405`, cross-user `403` |

---

## 6.1 Context Token Logging & Observability

For every authorized request passing through the Gateway (PEP #2), a short-lived **Context Token** (`hearth-ctx+jwt`) is minted and forwarded to the downstream microservice.

- **Gateway Logs (`docker compose logs -f api-gateway`)**:
  ```log
  ================================================================================
  [CONTEXT_TOKEN_GENERATED] Target Service: [nas-orchestrator]
    Request : GET /api/v1/nas/files/list
    Subject : resident01 (Role: RESIDENT, SID: ...)
    Intent  : nas.workspace.list (Action: READ)
    Token   : eyJhbGciOiJFUzI1NiIsImtpZCI6ImdhdGV3YXktc2lnLXYxIiwidHlwIjoiaGVhcnRoLWN0eCtqd3QifQ...
  ================================================================================
  ```
- **Downstream Logs (`docker compose logs -f nas-orchestrator element-registry video-service streaming-service`)**:
  ```log
  [CONTEXT_TOKEN_ACCEPTED] Service [nas-orchestrator] verified token: user=resident01 role=RESIDENT intent=nas.workspace.list action=READ
  ```
- **Policy-Registry Logs (`docker compose logs -f policy-registry`)**:
  ```log
  DecideRequest received: domain='NAS', intent/rule='nas.workspace.list', action='READ', subject='resident01' (role='RESIDENT'), resource='WORKSPACE:resident01' (qualifier=''), namespace='OWN'
  DecideResponse sent: effect='ALLOW', scope='OWN', reason='RULE:NAS.WORKSPACE.OWN.READ'
  ```
- **Postman & Newman Console**:
  The collection includes a top-level test event that captures `X-Hearth-Context` and `X-Hearth-Target-Service` headers, logging each minted token and intended service directly to the Postman/Newman console:
  ```log
  [CONTEXT TOKEN] Target Service: [nas-orchestrator]
  [CONTEXT TOKEN] Request: GET /api/v1/nas/files/list
  [CONTEXT TOKEN] Token: eyJhbGciOiJFUzI1NiIsImtpZCI6ImdhdGV3YXktc2lnLXYxIiwidHlwIjoiaGVhcnRoLWN0eCtqd3QifQ...
  ```

---

## 7. Newman CLI

Run the entire collection headlessly (CI/CD-friendly):

### Install Newman
```bash
npm install -g newman
```

### Run All Folders
```bash
newman run postman/Hearth-AuthChain-Postman.json \
  --env-var "base_url=https://localhost:8443" \
  --env-var "mgmt_url=http://localhost:8081" \
  --env-var "owner_username=hearth_owner" \
  --env-var "owner_password=ChangeMe123!" \
  --env-var "resident_username=resident01" \
  --env-var "resident_password=Resident@123" \
  --env-var "guest_username=guest01" \
  --env-var "guest_password=Guest@123" \
  --env-var "VIDEO_SVC_CLIENT_ID=video-service" \
  --env-var "VIDEO_SVC_SECRET=video-svc-secret-change-me" \
  --env-var "element_id=elem-living-room-01" \
  --insecure \
  --reporters cli,json \
  --reporter-json-export newman-results.json
```

> [!TIP]
> The `--insecure` flag disables SSL certificate verification for the self-signed gateway cert. Remove this flag in production with a proper certificate chain.

### Run a Single Folder
```bash
newman run postman/Hearth-AuthChain-Postman.json \
  --folder "01 · Auth – Login (public routes)" \
  --insecure \
  --env-var "base_url=https://localhost:8443" \
  --env-var "owner_username=hearth_owner" \
  --env-var "owner_password=ChangeMe123!"
```

### HTML Report (with newman-reporter-htmlextra)
```bash
npm install -g newman-reporter-htmlextra

newman run postman/Hearth-AuthChain-Postman.json \
  --insecure \
  --reporters htmlextra \
  --reporter-htmlextra-export newman-report.html
```
Open `newman-report.html` in a browser for a full visual test report.

---

*This file is maintained alongside `Hearth-AuthChain-Postman.json` in the `postman/` directory.*
