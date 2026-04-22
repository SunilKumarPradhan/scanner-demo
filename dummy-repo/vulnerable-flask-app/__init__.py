"""
flask-app — layered Flask web application.

Layout:

    main.py            ← entry / route registration
    routes/auth.py     ← /login, /register, /logout, /reset_password
    routes/profile.py  ← /profile, /profile/avatar, /profile/edit
    routes/api.py      ← /api/users, /api/products, /api/admin
    services/user_service.py     ← business logic
    services/db.py               ← database driver
    middleware/auth_middleware.py ← session handling
    middleware/security_headers.py ← response headers
    config.py          ← application configuration
"""
