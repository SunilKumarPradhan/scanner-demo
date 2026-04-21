"""
vulnerable-flask-app — comprehensive Flask DAST/SAST target.

Layout (mirrors a real layered web app so context_gatherer_node can
trace request → handler → service → DB):

    main.py            ← entry / route registration
    routes/auth.py     ← /login, /register, /logout, /reset_password
    routes/profile.py  ← /profile, /profile/avatar, /profile/edit
    routes/api.py      ← /api/users, /api/products, /api/admin
    services/user_service.py     ← business logic
    services/db.py               ← raw DB driver (SQL injection sinks)
    middleware/auth_middleware.py ← session check (broken)
    middleware/security_headers.py ← MISSING headers
    config.py          ← hardcoded secrets

Each route deliberately maps to one of Raven's specialised fixers:
  • injection_fixer  → SQLi / XSS / command / template injection
  • header_fixer     → CSP, HSTS, CORS, cookie flags
  • auth_fixer       → session / CSRF / access control
  • general_fixer    → crypto, info-disclosure, deserialisation
"""
