# Working folder: `C:\Users\Student\Downloads\QCMAIN`

You said **QCMAIN** is where “everything” lives. On disk that folder is a **workspace**: multiple snapshots, dashboards, and subfolders — it is **not** necessarily a single Git repository.

## What we verified

- **`QCMAIN`** itself has **no** `.git` at the top level (not one git repo for the whole tree).
- **`QCMAIN\QueenCalifia_Omega`** has a `.git` folder but **no `origin` remote** in `config` — so `git pull origin main` will **fail** there until you add a remote (or use a different clone).

## The repo that tracks GitHub `main`

The clone that matches **`https://github.com/HeruAhmose/QueenCalifia-CyberAI`** and can **`git pull`** is typically:

`C:\Users\Student\Downloads\QueenCalifia-CyberAI`

(Open **that** folder in Cursor if you want the assistant to run `git pull` against the same tree you push to GitHub.)

## Options to align QCMAIN with GitHub

**A — Recommended:** Keep one canonical clone and use QCMAIN for extras only  

- Daily work + training scripts:  
  `cd C:\Users\Student\Downloads\QueenCalifia-CyberAI`  
  `git pull origin main`

**B — Put the full repo inside QCMAIN**

```powershell
cd C:\Users\Student\Downloads\QCMAIN
git clone https://github.com/HeruAhmose/QueenCalifia-CyberAI.git QueenCalifia-CyberAI
cd QueenCalifia-CyberAI
```

Then open `QCMAIN\QueenCalifia-CyberAI` in Cursor.

**C — Attach `QueenCalifia_Omega` to GitHub** (only if you intend that folder to be the same project and history is compatible)

```powershell
cd C:\Users\Student\Downloads\QCMAIN\QueenCalifia_Omega
git remote add origin https://github.com/HeruAhmose/QueenCalifia-CyberAI.git
git fetch origin
# Then align branches (may need merge/rebase — get help if unsure)
```

## Training scripts

They live in **`scripts\`** on **`main`**. Run them from the **root of the GitHub-linked clone**, not from a random subfolder under QCMAIN unless that subfolder is that same clone.

See also: [`TRAINING_WINDOWS.md`](TRAINING_WINDOWS.md).
