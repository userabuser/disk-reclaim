# Developer Workstation Disk Reclamation & Churn Analysis Guide (Drive C:)

## 1. Executive Summary & Machine Diagnostics

On this workstation, Drive C: is in a critical low-storage condition:
- **Total Capacity**: 455.37 GB
- **Used Space**: 451.55 GB
- **Free Space Remaining**: **~3.82 GB** (< 1% remaining)

### Reclaimable Breakdown Identified on C:
| Category | Component / Target | Reclaimable Space | Risk Level |
| :--- | :--- | :--- | :--- |
| **Package Caches** | npm Download Cache (`npm-cache`) | **~6,025 MB (5.88 GB)** | **Low Risk** (Safe, re-downloads on demand) |
| **Package Caches** | Python Pip Cache (`pip\cache`) | **~3,511 MB (3.43 GB)** | **Low Risk** (Safe, re-downloads on demand) |
| **System Temp** | User Temp (`$env:TEMP`) | **~2,387 MB (2.33 GB)** | **Zero Risk** (Pure ephemeral, in-use locked files preserved) |
| **Package Caches** | Scoop Installer Cache (`scoop\cache`) | **~964 MB (0.94 GB)** | **Low Risk** (Installers no longer needed after install) |
| **Package Caches** | .NET NuGet Global Cache (`.nuget\packages`) | **~917 MB (0.90 GB)** | **Low Risk** (Re-fetched on `dotnet restore`) |
| **Build Caches** | Go Build Cache (`go-build`) | **~760 MB (0.74 GB)** | **Low Risk** (Recompiled on build) |
| **Editor Caches** | VS Code CachedData & V8 Bytecode | **~466 MB (0.45 GB)** | **Zero Risk** (Regenerated on launch) |
| **Diagnostics** | Application Crash Dumps (`CrashDumps`) | **~337 MB (0.33 GB)** | **Zero Risk** (Disposed fault snapshots) |
| **Browser Caches** | Chrome Cache Data & GPU Shaders | **~238 MB (0.24 GB)** | **Zero Risk** (History/logins untouched) |
| **Build Caches** | Cargo Crate Tarballs (`.cargo\registry\cache`)| **~43 MB (0.04 GB)** | **Low Risk** (Re-downloaded on build) |
| **Windows Update** | SoftwareDistribution Download Staging | **~4 MB** | **Zero Risk** (Already installed update payloads) |
| **Docker VHDX** | Docker WSL Virtual Disk (`docker_data.vhdx`) | **~9,224 MB (9.22 GB)** | **Special** (Requires VHD compact) |
| **IMMEDIATE RECLAIM TOTAL** | *Direct File/Cache Purge* | **~15.29 GB** | *(Brings free space from 3.8GB to ~19.1GB)* |

---

## 2. Risk Assessment Matrix

| Tier | Category | Risk Profile | Why It Is Safe | Side Effects / Residual Impact |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1: Zero Risk** | User Temp (`$env:TEMP`), Windows Temp, Crash Dumps (`.dmp`), WER Reports, Update Download Cache, VS Code/Chrome GPU & Bytecode Caches | **Zero Risk** | Purely ephemeral and diagnostics. The script automatically checks file locks and preserves active/in-use files. | None. Editors and browsers recompile cached UI shaders transparently in milliseconds. Crash dumps are unneeded diagnostics. |
| **Tier 2: Low Risk** | npm, pip, scoop, cargo, nuget, go build caches | **Low Risk** | Local package managers store tarballs/wheels so subsequent installs use local disk rather than internet bandwidth. Deleting them does **not** break existing installed libraries or project dependencies. | The next time you run `npm install`, `pip install`, or `dotnet restore` for an un-cached package, it will download over the network instead of using disk cache. |
| **Special: WSL/Docker** | `docker_data.vhdx` (9.22 GB) | **Low Risk** | WSL2 virtual hard disks expand dynamically but never automatically shrink when containers/images are pruned inside Linux. | Requires stopping WSL (`wsl --shutdown`) and running `diskpart` compact. |

---

## 3. The `Invoke-DiskReclaim.ps1` Toolset

The script [`Invoke-DiskReclaim.ps1`](file:///c:/Users/Nobody/Documents/antigravity/valiant-rutherford/Invoke-DiskReclaim.ps1) provides 4 primary operational modes:

### Mode A: Dry Run / Scan (`-Mode Scan`)
Performs a fast .NET inventory across all targets on C: without touching or modifying any files.
```powershell
pwsh -File .\Invoke-DiskReclaim.ps1 -Mode Scan
```
*To inspect only Zero-Risk items:*
```powershell
pwsh -File .\Invoke-DiskReclaim.ps1 -Mode Scan -Tier ZeroRisk
```

### Mode B: Safe Execution / Clean (`-Mode Clean`)
Safely purges caches. Skips files currently in use by active software, uses native CLI purge commands when available (`npm cache clean`, `pip cache purge`, `scoop cache rm *`, `go clean`), and removes orphan directories bottom-up.
```powershell
# Clean both ZeroRisk and LowRisk (Reclaims ~15.3 GB):
pwsh -File .\Invoke-DiskReclaim.ps1 -Mode Clean -Tier All

# Clean ONLY ZeroRisk (Pure ephemerals, reclaims ~3.4 GB):
pwsh -File .\Invoke-DiskReclaim.ps1 -Mode Clean -Tier ZeroRisk
```

### Mode C: Real-Time Process & Workflow Monitor (`-Mode Monitor`)
Monitors which applications and development processes are actively causing disk write churn:
1. **Cumulative Lifetime Writes**: Shows which applications have written the most gigabytes since launch (e.g. Chrome, Antigravity, VS Code, OneDrive, Signal, Codex).
2. **Real-time Velocity Sampling**: Measures actual write throughput (MB/s) over an interval (default 5 seconds) to catch runaway write loops.
```powershell
pwsh -File .\Invoke-DiskReclaim.ps1 -Mode Monitor -MonitorDurationSec 5
```

### Mode D: Session Churn Hunter (`-Mode FindChurn`)
When switching between branches, running build compilers, testing Docker, or launching development servers, user sessions often generate huge ephemeral files (crash dumps, installer stashes, `.tmp` scratch files, uncompressed bundles).

This mode scans Drive C: using an ultra-fast stack traversal (skipping `.git`, `node_modules`, and virtualenvs) to locate all recently created/modified files above a given size threshold:
```powershell
# Find files >= 20 MB created/modified within the past 48 hours:
pwsh -File .\Invoke-DiskReclaim.ps1 -Mode FindChurn -ChurnHours 48 -ChurnMinMB 20
```

---

## 4. Special Optimization: Reclaiming Docker WSL Virtual Disk (9.2 GB)

The file `C:\Users\Nobody\AppData\Local\Docker\wsl\disk\docker_data.vhdx` is currently consuming **9.22 GB** on Drive C:.

### Step-by-Step VHDX Compacting Instructions:
1. Close Docker Desktop.
2. Terminate WSL instances from an elevated PowerShell:
   ```powershell
   wsl --shutdown
   ```
3. Open `diskpart`:
   ```powershell
   diskpart
   ```
4. In the `DISKPART>` prompt, execute:
   ```text
   select vdisk file="C:\Users\Nobody\AppData\Local\Docker\wsl\disk\docker_data.vhdx"
   attach vdisk readonly
   compact vdisk
   detach vdisk
   exit
   ```
This immediately releases unused virtual disk blocks back to Windows Drive C:.
