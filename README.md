# SERO - Framework C2 Avancé

> **Framework complet de commande et contrôle pour évaluations de sécurité autorisées**

Framework complet et hautement configurable de commande et contrôle (C2) avec serveur WPF et client stub avancé. Offre des capacités de persistance multi-vecteurs, de protections anti-analyse sophistiquées, un crypter intégré polymorphique et une communication sécurisée via TLS pinning.

> [!NOTE]
> **Crypter — Packer LZNT1 intégré**
>
> Le payload est compressé LZNT1 puis chiffré AES-256-CBC. NativeAOT + crypter ≈ **2,5MB** (vs 22 MB en word-encoding). Décompression via `ntdll!RtlDecompressBuffer` — pas de dépendance externe, absent de l'IAT.

---

<div align="center">
  <img width="49%" alt="image" src="dashboard.png" />
  <img width="49%" alt="Dashboard SERO" src="builder.png" />
</div>



## Caractéristiques Principales

### Serveur
- Interface WPF moderne avec thème sombre et icône projet dans le header
- Gestion multi-clients avec déduplication par HWID et InstanceId
- Panel de clients en temps réel — uptime rafraîchi toutes les secondes
- `INotifyPropertyChanged` sur `ConnectedClient` — plus de `Items.Refresh()` global, zéro freeze avec des milliers de clients
- AutoTask — Exécution conditionnelle de commandes par HWID
- **Backup serveur `.sero`** : export/import cert TLS + clé d'auth en un seul fichier — restauration complète sur nouvelle machine en un clic
- Configuration persistante en JSON — sauvegarde uniquement via bouton Save (plus d'auto-save à la fermeture)
- Logs détaillés de toutes les connexions et actions
- Virtualisation DataGrid pour gérer des milliers de clients
- Builder intégré avec compilation NativeAOT + SingleFile

### Client Stub
- Connexion multi-host failover (redondance serveur)
- Support Pastebin pour configuration à distance
- Mutex optionnel pour forcer une seule instance
- Persistance configurable multi-vecteurs
- Protections anti-analyse avancées
- Watchdog anti-kill avec guardians multi-processus
- Crypter polymorphique **LZNT1 + AES-256-CBC** — NativeAOT+crypter ~3 MB (vs ~22 MB avant)
- Process Hollowing 64bit (NativeAOT uniquement)
- Icône personnalisable et métadonnées assembly copiables
- BuildId unique par build (hash différent même avec sources identiques)

## Fonctionnalités Runtime

### Remote Shell
- Shell interactif en temps réel avec le client
- Exécution de commandes DOS/PowerShell
- Support complet des arguments et redirections
- Output streaming vers le serveur

### Remote Execute File
- Upload et exécution de fichiers à distance (exe, dll, scripts)
- Paramètres personnalisés pour chaque exécution
- Récupération du résultat d'exécution

### HollowExec
- Exécution d'un PE arbitraire en mémoire via process hollowing
- Injecte dans un processus cible configurable sans écriture disque

### Élévation UAC (runtime stub)
- Demande d'élévation avec retry loop optionnel
- Résultat retourné au serveur (succès/échec + message)

### UAC Bypass + SYSTEM (crypter loader)

![UAC Bypass Demo](./uacbypdemo-ezgif.com-optimize.gif)

- **Étape 1 — computerdefaults bypass** : hijack `HKCU\Software\Classes\ms-settings\Shell\Open\command` + `DelegateExecute` → `computerdefaults.exe` se lance élevé (moins détecté que fodhelper), reexécute le loader
- **Étape 2 — SYSTEM elevation** : `SeDebugPrivilege` → trouve le PID de winlogon.exe → duplique son token → `CreateProcessWithTokenW` avec le token SYSTEM
- Toutes les strings sensibles AES-chiffrées, advapi32/shell32 chargés dynamiquement (absents de l'IAT)
- `TerminateProcess(GetCurrentProcess(),0)` après le bypass — évite la boîte de dialogue "saturation mémoire tampon" du CRT
- **Note** : avec UAC Bypass activé, le loader ne se connecte au C2 qu'une fois élevé — si l'élévation échoue le process se termine

### Update Client
- Remplacement du stub en cours d'exécution par une nouvelle version
- Relance automatique depuis le chemin installé

## Architecture Réseau

- **Protocole TLS 1.2+** avec certificate pinning (vérification SHA256)
- **Authentification par clé partagée** (32 caractères) vérifiée à chaque connexion
- **Heartbeat toutes les 10 secondes** + mesure RTT (ping/pong)
- **Reconnexion automatique** avec délai configurable (défaut 5 secondes)
- **Résolution géographique** des IP via ip-api.com (country + code)

## Identité Client

- **Hardware ID (HWID)** basé sur propriétés système
- **Instance ID unique** (8 caractères aléatoires par session)
- **Déduplication intelligente** serveur via clé composite HWID + InstanceId
- **Tag client** persistant via DataStore JSON

## Persistance

Le stub se copie dans `%AppData%\Roaming\<PersistName>\<HiddenFileName>` avec nom configurable. Trois méthodes combinables :

| Méthode | Visibilité | Implémentation |
|---------|-----------|----------------|
| Registry `HKCU\Run` | Visible onglet Démarrage | `RegSetValue` |
| Startup Folder `.lnk` | Visible onglet Démarrage | COM WScript.Shell via PowerShell |
| Scheduled Task | Invisible onglet Démarrage | `Register-ScheduledTask` AtLogOn |

### Watchdog de Persistance
- **Lock fichier** (FileShare.Read) sur l'exe installé, le backup et le .lnk — empêche la suppression
- **Backup caché** dans `%LocalAppData%\Microsoft\WindowsServices\svchost.dat` (attributs Hidden+System)
- **FileSystemWatcher** sur le dossier d'installation — restauration instantanée si l'exe est supprimé
- **FileSystemWatcher** sur le dossier Startup — recrée le .lnk immédiatement
- **Polling toutes les 5 secondes** comme fallback (vérifie exe + backup + registry + startup + task)
- **WMI Permanent Event Subscription** dans `root\subscription` — relance l'exe même si tous les processus sont tués simultanément, persiste après reboot, indépendant de nos processus

## Watchdog Anti-Kill

![2026-04-1212-57-31-ezgif com-optimize (1)](https://github.com/user-attachments/assets/bc7818a6-3594-4008-b133-887f419cbe6e)

### Mécanisme Guardian
4 processus guardians indépendants surveillent le processus principal :

**Mode RunPE (NativeAOT + Hollowing) :**
| Guardian | Apparence dans le gestionnaire de tâches |
|----------|------------------------------------------|
| G1 | `dllhost.exe` (COM surrogate), parent=Explorer |
| G2 | `RuntimeBroker.exe`, parent=Explorer |
| G3 | `svchost.exe`, parent=Explorer |
| G4 | `SearchProtocolHost.exe`, parent=Explorer |

**Mode SingleFile :**
Les guardians sont des copies du stub lancées avec PPID spoofing vers Explorer. Moins furtifs que le mode RunPE (pas d'injection dans un processus système), mais protégés par DACL anti-terminate. Le filet de secours **WMI** (`root\subscription`) relance le client même si tous les processus sont tués simultanément (nécessite droits admin).

- **Spawn échelonné** : 150ms entre chaque guardian — fenêtre de kill simultané quasi impossible
- **Mutex d'arbitrage** — si deux guardians détectent la mort du main simultanément, un seul relance
- **PPID spoofing** sur tous les guardians ET sur le relancement du main — aucun n'apparaît comme enfant de l'autre
- **WaitForExit** avec fallback polling 1s si DACL bloque SYNCHRONIZE

### DACL Anti-Terminate
- ACE DENY `PROCESS_TERMINATE` pour Everyone — bloque `TerminateProcess()` depuis l'extérieur
- ACE ALLOW `0x001FFFFE` pour Everyone — permet `WaitForExit`/`HasExited` au guardian
- Retiré proprement lors de la désinstallation

### SetCriticalProcess (optionnel)
- `NtSetInformationProcess(ProcessBreakOnTermination)` — BSOD si le processus est terminé de force
- Nécessite droits administrateur

## Crypter

Le Builder génère un **loader C++ natif** polymorphique qui chiffre et lance le stub de manière furtive.

### Pipeline de chiffrement
1. **LZNT1** compresse le payload via `ntdll!RtlCompressBuffer` (ratio ~50% sur NativeAOT)
2. **AES-256-CBC** chiffre le payload compressé avec clé/IV aléatoires par build
3. L'overlay est appended au loader en **bytes bruts** : `MAGIC(8) + TOTAL_RAW(4) + ORIG_SIZE(4) + key(32) + iv(16) + encrypted`
4. Le loader lit l'overlay, déchiffre AES, décompresse via `ntdll!RtlDecompressBuffer`, lance le stub

**Taille output typique** : NativeAOT (~5 MB) → LZNT1 (~2.5 MB) → AES → **~3 MB final**

### Loader C++ natif
Le loader est un **binaire C++ compilé avec MSVC** (~150 KB) — zéro metadata .NET, zéro runtime, surface d'attaque minimale :

- **Toutes les strings sensibles chiffrées en AES** (noms d'APIs, DLLs, chemins) — invisibles dans `strings` / PE Bear
- **Chargement dynamique** de toutes les APIs via export-table walk (PEB + `PeGetProc`) — table d'imports vide de toute API suspecte
- **UAC bypass** : `advapi32.dll`, `shell32.dll` et leurs fonctions (`OpenProcessToken`, `AdjustTokenPrivileges`, `DuplicateTokenEx`, `RegCreateKeyExW`, `ShellExecuteExW`, etc.) chargés dynamiquement — absents de l'IAT
- **Strings UAC chiffrées** : `computerdefaults.exe`, `ms-settings\Shell\Open\command`, `winlogon.exe`, `SeDebugPrivilege`, `DelegateExecute` — toutes AES-chiffrées, construites en mémoire au runtime
- **Décompression LZNT1** via `ntdll!RtlDecompressBuffer` — toujours disponible, absent de l'IAT (chargé via PEB walk)
- **`user32.dll` absent de la table d'imports** — compilé sans CRT (`/NODEFAULTLIB /EHs-c-`)
- **Anti-sandbox** : uptime > 5min + vérification timing spin-loop (emulateurs ignorent le spin)
- **8 fonctions mortes** générées aléatoirement à chaque build (noms et corps différents)

### Polymorphisme
- Noms des fonctions junk générés aléatoirement à chaque build
- Clé AES des strings différente à chaque build (splitée en 3 parties dans le binaire)
- Clé/IV AES du payload différents à chaque build
- Magic bytes overlay 8 octets aléatoires par build (pas de signature statique)
- BuildId GUID unique compilé dans le stub (hash binaire différent même avec sources identiques)
- Ordre des appels junk shufflé aléatoirement


## Protections Anti-Analyse

Toutes les protections sont configurables indépendamment dans le Builder. Si une protection détecte un environnement suspect, le stub se termine silencieusement sans connexion.

### Anti-Debug
- `IsDebuggerPresent()` — vérification API Win32
- `CheckRemoteDebuggerPresent()` — vérification du processus courant
- `NtQueryInformationProcess(ProcessDebugPort=7)` — détection kernel-mode
- Timing check via `Thread.SpinWait` — delta > 500ms = debugger step détecté
- `NtSetInformationThread(ThreadHideFromDebugger=0x11)` — se cache de tous les debuggers

### Anti-VM
- BIOS Registry : keywords VMware, VirtualBox, VBOX dans `HARDWARE\DESCRIPTION\System\BIOS`
- Clé `SOFTWARE\VMware, Inc.\VMware Tools`
- Clé `SOFTWARE\Oracle\VirtualBox Guest Additions`

### Anti-Detect
- Scan de tous les processus en cours contre une liste noire : ollydbg, x64dbg, x32dbg, ida, ida64, windbg, dnspy, dotpeek, processhacker, procmon, procexp, wireshark, fiddler, charles, tcpview, pestudio, die, lordpe, pe-bear, sandboxie, cuckoo, regmon, filemon, autoruns, httpdebugger, resourcehacker
- Scan du nom d'utilisateur courant contre une liste de noms suspects (sandbox, virus, malware, analyst, etc.) — comparaison insensible à la casse
- Détection de région via registre Windows (`HKCU\Control Panel\International\LocaleName`) — compatible `InvariantGlobalization=true`
- Scoring : fichiers récents < 3 **et** disque < 40GB → flaggé (double condition pour éviter les faux positifs)

### Anti-Sandbox
- Scoring system : 3+ indicateurs requis pour déclencher
  - Uptime < 3 minutes (`Environment.TickCount64`)
  - Sleep-skip détecté : `Thread.Sleep(500)` vérifié au `Stopwatch` — si < 400ms → +2 points (indicateur fort)
  - Fichiers temp < 3 dans `%TEMP%`
  - RAM physique totale < 1GB (`GlobalMemoryStatusEx`)
  - Programmes installés < 8 (`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`)

## Build et Optimisation

### SingleFile (sans injection)
```
dotnet publish -r win-x64 --self-contained
  -p:PublishSingleFile=true -p:PublishTrimmed=true -p:TrimMode=full
  -p:InvariantGlobalization=true -p:EnableCompressionInSingleFile=true
```
- Trimming agressif + compression des assemblies embarquées
- Fichier plus lourd

### NativeAOT + RunPE
```
dotnet publish -r win-x64
  -p:PublishAot=true -p:InvariantGlobalization=true
  -p:IlcOptimizationPreference=Size -p:IlcGenerateStackTraceData=false
```
- Code machine natif — impossible à décompiler avec dnSpy/ILDasm
- Process hollowing dans un processus légitime configurable
- Taille typique ~4MB 

## Plateformes Supportées

**Runtime** : .NET 10.0+ (Windows 10 minimum)  
**Architecture** : x64 uniquement

| OS | Testé |
|----|-------|
| Windows 11 | ✅ |
| Windows 10 | ✅ |
| Windows Server 2022 | ✅ |
| Windows Server 2019 | ✅ |

## Configuration du Builder

**CONNECTION**
- Hosts : liste des serveurs en failover (IP/DNS)
- Port : port d'écoute (défaut 7777)

**IDENTITY**
- Client ID Prefix : préfixe d'identification
- Copy Assembly Metadata : copie les propriétés d'un exe légitime (nom produit, société, version)
- Custom Icon : icône personnalisée (.ico)

**PERSISTENCE**
- Registry (HKCU\Run)
- Startup Folder (.lnk)
- Scheduled Task (invisible)
- Watchdog de persistance (FileSystemWatcher + WMI + backup)

**PROTECTION**
- Anti-Debug
- Anti-VM
- Anti-Detect
- Anti-Sandbox
- Anti-Kill (DACL + guardians watchdog)
- SetCriticalProcess (BSOD — admin requis)
- Process Hollowing (NativeAOT uniquement)

**CRYPTER**
- Wrap le stub dans un loader AES+word-encoding polymorphique (entropie ~3.5 bits/byte)
- Option **UAC Bypass + SYSTEM elevation** : fodhelper + vol de token winlogon — toutes les strings/APIs obfusquées
- Disponible en NativeAOT ou SingleFile fallback

## Structure du Projet

```
sero/
├── server/                      # Serveur C2 (WPF, .NET 10)
│   ├── UI/
│   │   ├── ServerWindow.xaml(.cs)        # Fenêtre principale + Builder + Loader
│   │   ├── RemoteShellWindow.xaml(.cs)   # Shell interactif
│   │   ├── ClientLogWindow.xaml(.cs)     # Logs clients
│   │   └── TagDialog.xaml(.cs)           # Tags clients
│   ├── Builder/
│   │   └── Crypter.cs                    # Logique crypter (AES+GZip, génération loader C++)
│   ├── Stubs/
│   │   └── loader.cpp                    # Source du loader C++ natif (généré+compilé par build)
│   ├── Net/
│   │   ├── TlsServer.cs                  # Serveur TLS + routing packets
│   │   ├── CertificateHelper.cs          # Gestion certificats
│   │   └── SeroDiscordRPC.cs             # Discord Rich Presence (optionnel)
│   ├── Data/
│   │   ├── DataStore.cs                  # Stockage JSON
│   │   ├── ClientRecord.cs               # Enregistrement client
│   │   ├── ConnectedClient.cs            # Session active
│   │   └── AutoTask.cs                   # Tâches automatiques par HWID
│   ├── Protocol/
│   │   └── Packet.cs                     # Définition protocole + data classes
│   └── SeroServer.csproj
│
├── stub/                        # Client stub (.NET 10)
│   ├── Program.cs                # Point d'entrée + init protections
│   ├── TlsClient.cs              # Client TLS + gestion commandes
│   ├── Protection.cs             # Anti-analyse + watchdog guardians + WMI
│   ├── Persistence.cs            # Registry + Startup + Task + watchdog fichiers
│   ├── ProcessHollowing.cs       # RunPE NativeAOT + SpawnDetached PPID-spoof
│   ├── Config.cs                 # Configuration compilée par le Builder
│   ├── StubLog.cs                # Logging interne
│   └── SeroStub.csproj
│
├── .gitignore
└── README.md
```

## Limitations & Bugs Connus

- `SetCriticalProcess` (BSOD) nécessite droits administrateur
- Le Process Hollowing avec élévation UAC nécessite au moins une persistence activée (le stub ne peut pas retrouver son propre exe via `Environment.ProcessPath` qui retourne le processus hôte)
- Le watchdog WMI peut être détecté par les EDR qui surveillent `root\subscription`
- **Multi-host failover non-fonctionnel** : le Builder ne compile que le premier host dans `Config.Host` — les hosts supplémentaires de l'UI ne sont pas utilisés par le stub
- **HWID instable (SessionId)** : `GetHwid()` inclut le `SessionId` — une reconnexion RDP ou déconnexion Windows génère un nouveau HWID, créant un doublon client dans le panel
- **`UpdateClient` en mode RunPE** : le script BAT attend la mort du PID de l'hôte (`dllhost.exe` etc.) qui ne se termine jamais — la mise à jour est bloquée indéfiniment en mode hollowing

## Conditions d'Utilisation

**Ce framework est fourni à titre éducatif et pour les tests de sécurité autorisés uniquement.**

### Utilisations Autorisées
- Engagements de red team avec autorisation écrite du client
- Tests de pénétration dans le cadre d'un contrat formel
- Recherche en sécurité académique ou professionnelle
- Analyse défensive d'environnements internes

### Utilisations Interdites
- Déploiement sans consentement explicite du propriétaire des systèmes
- Exfiltration ou vol de données
- Cyberattaques ou perturbation de services
- Toute activité illégale ou malveillante

**Les utilisateurs sont seuls responsables du respect des lois applicables dans leur juridiction.**

---

**Développé par** : SeroSkiid  
**Version** : 2.0  
**Dernière mise à jour** : Avril 2026
**Crédit pour le process hollowing** : Hydra48 aKa le Maitre de l'API win32 https://github.com/hydra48/process-hollowing-24h2 
