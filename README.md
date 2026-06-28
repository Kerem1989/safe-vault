# SafeVault

A secure ASP.NET Core MVC web application demonstrating defense-in-depth security practices: input validation, authentication, role-based authorization, and protection against SQL injection and XSS attacks. Built across three security-focused activities and verified with an xUnit test suite.

## Overview

SafeVault is an account-management application built on **ASP.NET Core 8 (MVC)** and **ASP.NET Core Identity**. It was developed in three stages, each hardening a different security layer:

1. **Input validation** — reject SQL-injection and XSS payloads at the boundary.
2. **Authentication & authorization** — verify credentials and gate features by role.
3. **Vulnerability remediation** — eliminate SQL injection and XSS, with attack-simulating tests.

## Security features

- **Input validation** (`ValidationHelpers`)
  - `IsValidUsername` — accepts ordinary usernames; rejects null/empty/whitespace and characters used in SQL injection (`' ; -- =`) and XSS (`< > / script`).
  - `IsValidEmail` — accepts well-formed addresses; rejects malformed input and injection/markup payloads.
  - `Sanitize` — HTML-encodes output so injected markup is rendered inert (defense in depth on top of Razor's auto-encoding).
- **Authentication** — login backed by ASP.NET Core Identity (`SignInManager.PasswordSignInAsync`); passwords are salted and hashed by Identity (PBKDF2). Usernames are validated *before* any credential check, so injection input never reaches the data layer.
- **Role-based authorization (RBAC)** — roles (`Admin`, `User`) seeded at startup and assigned at registration (`@admin.com` → Admin, otherwise User). The Admin Dashboard is protected with `[Authorize(Policy = "Admin")]`.
- **SQL injection protection** — all data access goes through Entity Framework Core / Identity, which parameterizes every query. No raw SQL or string concatenation in application code.
- **XSS protection** — Razor views auto-encode all output; no `Html.Raw` usage. Combined with input validation and `Sanitize`, this provides layered mitigation.

## Tech stack

- ASP.NET Core 8 MVC
- ASP.NET Core Identity
- Entity Framework Core (SQL Server)
- xUnit + Moq (tests)

## Project structure

```
SafeVault/
├── Controllers/        # AccountController (login/register), HomeController (Dashboard, public pages)
├── Data/               # ApplicationDbContext, RoleSeeder
├── Models/             # User, LoginViewModel, ErrorViewModel
├── Utilities/          # ValidationHelpers (input validation & sanitization)
├── Views/              # Razor views
└── Program.cs          # Identity, authorization policy, and middleware wiring

SafeVault.Tests/
├── TestInputValidation.cs   # SQL injection & XSS payload rejection, sanitization
├── TestAuthentication.cs    # login success/failure paths, role assignment on register
├── TestAuthorization.cs     # Admin policy on Dashboard, public pages unrestricted
└── MockHelpers.cs           # mock factories for Identity managers
```

## Getting started

### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download)
- SQL Server (or update the connection string for your provider)

### Configure the database

Set the `SQLServerIdentityConnection` connection string in `appsettings.json`, then apply migrations:

```bash
dotnet ef database update --project SafeVault
```

### Run the app

```bash
dotnet run --project SafeVault
```

### Run the tests

```bash
dotnet test SafeVault.Tests/SafeVault.Tests.csproj
```

All 45 tests should pass.

## Testing

The suite simulates real attack scenarios:

- **SQL injection** — payloads such as `' OR '1'='1` and `'; DROP TABLE Users;--` are rejected by username validation.
- **XSS** — payloads such as `<script>alert('xss')</script>` and `<img src=x onerror=alert(1)>` are rejected or HTML-encoded.
- **Authentication** — valid/invalid credentials, unknown users, and injection usernames (which must never reach the credential check).
- **Authorization** — the Admin Dashboard requires the Admin policy; public pages stay open.

## Security notes

This project is an educational demonstration of secure coding practices and is not hardened for production deployment.
