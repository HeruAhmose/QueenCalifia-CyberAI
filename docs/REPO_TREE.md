# QC OS — Repo Tree (v4.2.1)

```
.
├── .firebaserc
├── .gitignore
├── README.md
├── render.yaml
├── run-local.ps1
├── firebase.json          # legacy Firebase Hosting (optional)
├── gcp/
│   └── dashboard-hosting/ # GCS deploy script + README
├── docs/
│   ├── API_CONTRACT.md
│   ├── DEPLOY_DASHBOARD_GCS.md
│   ├── REPO_TREE.md
│   └── TRIPLE_CORE_BUILD_PLAN.md
├── backend/
│   ├── .env.example
│   ├── README.md
│   ├── app.py
│   ├── requirements.txt
│   ├── requirements-quant.txt
│   ├── core/
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── database.py
│   │   └── settings.py
│   └── modules/
│       ├── __init__.py
│       ├── conversation/
│       │   ├── __init__.py
│       │   ├── engine.py
│       │   └── routes.py
│       ├── market/
│       │   ├── __init__.py
│       │   ├── engine.py
│       │   └── routes.py
│       ├── forecast/
│       │   ├── __init__.py
│       │   ├── engine.py
│       │   └── routes.py
│       ├── identity/
│       │   ├── __init__.py
│       │   ├── engine.py
│       │   ├── missions.py
│       │   ├── provider.py
│       │   └── routes.py
│       └── quantum/
│           ├── __init__.py
│           └── worker.py
└── frontend/
    ├── .env.development
    ├── .env.production
    ├── index.html
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── App.jsx
        ├── index.css
        ├── main.jsx
        ├── lib/
        │   └── api.js
        └── panels/
            ├── panels.css
            ├── IdentityPanel.jsx
            ├── LearningDock.jsx
            ├── ModelManager.jsx
            └── CyberMissionPanel.jsx
```
