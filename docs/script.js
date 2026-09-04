/* ══════════════════════════════════════════════════════════════════
   i18n — multi-language support (18 languages, auto-detect)
   ══════════════════════════════════════════════════════════════════ */
const LANGS = {
  en: {
    'nav.features':'Features','nav.showcase':'Showcase','nav.pricing':'Pricing',
    'hero.eyebrow':'open source · authorized use only',
    'hero.h1a':'The C2/RAT they charge','hero.h1b':'$2,000 for.','hero.h1c':'Free.',
    'hero.lead':'HVNC, DXGI remote desktop at 60fps, remote webcam via DirectShow, process hollowing with PPID spoof, NativeAOT stub — 40+ features. Everything the expensive ones have. None of the price tag.',
    'hero.cta1':'View on GitHub','hero.cta2':'Screenshots',
    's.features':'What it does.',
    'col.mon':'Monitoring','col.adm':'Administration','col.off':'Offensive',
    's.pricing':'The market.','s.pricing.sub':'What others charge for the same thing — often worse, and closed to inspect.',
    'price.closed':'commercial, closed source','price.leaked':'reversed & leaked anyway','price.ours':'Source available, full code on GitHub',
    's.showcase':'Real screenshots.','s.showcase.sub':'No mocked-up demos. Actual captures from the server.',
    's.tech':'No shortcuts.','s.tech.sub':'The details that separate a demo from something you\'d actually deploy.',
    's.hvnc':'HVNC in action.','s.hvnc.sub':'Live demo — hidden desktop, browser session, full control. No editing.',
    's.contrib':'Contributors.','s.contrib.sub':'People who built this.',
    'cta.h1':'Open source.','cta.h2':'No strings.',
    'cta.body':'Fork it. Build on it. Make it yours. Just use it on systems you have authorization for.',
    'cta.legal':'For authorized use only — red team engagements, security research, CTF. You are responsible for where you point it.',
    'dd.hvnc.h3':'Hidden Virtual Network Computing',
    'dd.hvnc.p1':'HVNC creates a completely isolated Windows desktop session — invisible to the target. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram and Explorer launch directly into the shadow session. The victim sees nothing. You see everything.',
    'dd.hvnc.p2a':'Each browser gets ','dd.hvnc.p2b':' and fills the HVNC frame. Mouse and keyboard forwarded with pixel-perfect accuracy. Clipboard synced on demand.',
    'dd.hvnc.tag1':'isolated desktop','dd.hvnc.tag2':'11 apps','dd.hvnc.tag3':'clipboard sync','dd.hvnc.tag4':'real-time input',
    'dd.runpe.h3':'Process Hollowing — RunPE x64',
    'dd.runpe.p1a':'No new file is dropped — the existing PE is mapped via ','dd.runpe.p1b':' into the target via ','dd.runpe.p1c':' — Windows resolves relocations and IAT automatically. The thread\'s RIP is redirected to the new entry point, then resumed.',
    'dd.runpe.p2a':'PPID spoofing via ','dd.runpe.p2b':' makes the injected process appear as a child of explorer.exe or winlogon.exe. Task Manager, Process Explorer — they see nothing suspicious.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'no disk write','dd.runpe.tag3':'PPID spoof','dd.runpe.tag4':'suspended create','dd.runpe.tag5':'memory remap',
    'dd.gui.h3':'WPF Interface — DevExpress',
    'dd.gui.p1':'Built on WPF with DevExpress 25.2. Sidebar navigation in NanoCore style — an icon rail on the left with labelled panels for each feature group. The entire UI adapts to the active theme in real time.',
    'dd.gui.p2':'A built-in theme picker offers 20+ presets — Sero Dark (default), DevExpress Dark, Office 2019 family, Visual Studio 2013 themes, The Bezier, and more. Themes apply live with no restart. Interface language switchable across 10 locales.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ themes','dd.gui.tag3':'10 languages','dd.gui.tag4':'live theme switch',
    'tech.tls.title':'TLS 1.2+ with certificate pinning','tech.tls.p':'Shared-key auth on every packet. 3s heartbeat with RTT measurement. Multi-host auto-reconnect with configurable round-robin delay.',
    'tech.ppid.title':'PPID spoofing in RunPE','tech.ppid.p':'UpdateProcThreadAttribute sets the injected process parent to explorer.exe or winlogon.exe depending on elevation level.',
    'tech.wd.title':'Watchdog that can\'t be killed','tech.wd.p':'4 guardian processes in dllhost/SearchProtocolHost with PPID spoofing, staggered 800ms apart. File lock + FileSystemWatcher for instant restore.',
    'feat.mon.1':'Remote Desktop — DXGI + GDI fallback','feat.mon.2':'HVNC — isolated hidden desktop','feat.mon.3':'Webcam — DirectShow + VFW','feat.mon.4':'Microphone — live listen + WAV save','feat.mon.5':'Keylogger — disk logging by date','feat.mon.6':'Performance Monitor — CPU / RAM / Net','feat.mon.7':'Remote Shell — cmd / PowerShell',
    'feat.adm.1':'File Manager — browse / upload / exec','feat.adm.2':'Process Manager — tree view, icons','feat.adm.3':'Registry Editor — HKLM + HKCU','feat.adm.4':'Service / Window / Device Manager','feat.adm.5':'TCP Connections + firewall rules','feat.adm.6':'Startup Manager','feat.adm.7':'Installed Programs — silent uninstall',
    'feat.off.1':'RunPE — in-memory + PPID spoof','feat.off.2':'Reverse SOCKS5 proxy','feat.off.3':'Crypto Clipper — 10 coins','feat.off.4':'AutoTask DLL plugins — C++, compiled on demand','feat.off.5':'XMR Miner — configurable hollow target','feat.off.6':'Telegram first-exec notification','feat.off.7':'Per-HWID AutoTask deduplication','hero.features':'40+ features','footer.built':'Built by ','footer.lic':' — authorized use only.',
  },
  fr: {
    'nav.features':'Fonctionnalités','nav.showcase':'Galerie','nav.pricing':'Tarifs',
    'hero.eyebrow':'open source · usage autorisé uniquement',
    'hero.h1a':'Le RAT/C2 vendu','hero.h1b':'2 000 $ ailleurs.','hero.h1c':'Gratuit.',
    'hero.lead':'HVNC, bureau distant DXGI à 60fps, webcam déportée via DirectShow, process hollowing + PPID spoof, stub NativeAOT — 40+ fonctionnalités. Tout ce qu\'ont les outils payants. Sans le prix.',
    'hero.cta1':'Voir sur GitHub','hero.cta2':'Captures d\'écran',
    's.features':'Ce qu\'il fait.',
    'col.mon':'Surveillance','col.adm':'Administration','col.off':'Offensif',
    's.pricing':'Le marché.','s.pricing.sub':'Ce que les concurrents facturent — souvent moins bien, et source fermée.',
    'price.closed':'commercial, source fermée','price.leaked':'restitué et leaké de toute façon','price.ours':'Source disponible, code complet sur GitHub',
    's.showcase':'Vraies captures.','s.showcase.sub':'Pas de démos trafiquées. Captures réelles du serveur.',
    's.tech':'Pas de raccourcis.','s.tech.sub':'Les détails qui séparent une démo d\'un outil réellement déployable.',
    's.hvnc':'HVNC en action.','s.hvnc.sub':'Démo live — bureau caché, session navigateur, contrôle total. Sans montage.',
    's.contrib':'Contributeurs.','s.contrib.sub':'Les gens qui ont construit ça.',
    'cta.h1':'Open source.','cta.h2':'Sans condition.',
    'cta.body':'Forkez. Construisez dessus. Faites-en le vôtre. Utilisez-le uniquement sur les systèmes que vous êtes autorisé à tester.',
    'cta.legal':'Usage autorisé uniquement — red team, recherche en sécurité, CTF. Vous êtes responsable de l\'usage que vous en faites.',
    'dd.hvnc.h3':'Bureau Réseau Virtuel Caché',
    'dd.hvnc.p1':'HVNC crée une session bureau Windows totalement isolée — invisible pour la cible. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram et Explorer se lancent directement dans la session fantôme. La victime ne voit rien. Vous voyez tout.',
    'dd.hvnc.p2a':'Chaque navigateur reçoit ','dd.hvnc.p2b':' et remplit le cadre HVNC. Souris et clavier transmis avec précision pixel par pixel. Presse-papier synchronisé à la demande.',
    'dd.hvnc.tag1':'bureau isolé','dd.hvnc.tag2':'11 applications','dd.hvnc.tag3':'sync presse-papier','dd.hvnc.tag4':'saisie temps réel',
    'dd.runpe.h3':'Creusement de Processus — RunPE x64',
    'dd.runpe.p1a':'Aucun fichier créé — le PE existant est mappé via ','dd.runpe.p1b':' dans la cible via ','dd.runpe.p1c':' — Windows résout relocalisations et IAT automatiquement. Le RIP du thread est redirigé vers le nouveau point d\'entrée, puis repris.',
    'dd.runpe.p2a':'Le PPID spoofing via ','dd.runpe.p2b':' fait apparaître le processus injecté comme enfant d\'explorer.exe ou winlogon.exe. Gestionnaire des tâches, Process Explorer — rien de suspect.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'sans écriture disque','dd.runpe.tag3':'PPID spoof','dd.runpe.tag4':'création suspendue','dd.runpe.tag5':'remap mémoire',
    'dd.gui.h3':'Interface WPF — DevExpress',
    'dd.gui.p1':'Construit sur WPF avec DevExpress 25.2. Navigation en barre latérale style NanoCore — un rail d\'icônes à gauche avec des panneaux étiquetés pour chaque groupe de fonctionnalités. Toute l\'interface s\'adapte au thème actif en temps réel.',
    'dd.gui.p2':'Un sélecteur de thèmes intégré propose plus de 20 thèmes — Sero Dark (par défaut), DevExpress Dark, famille Office 2019, thèmes Visual Studio 2013, The Bezier, et plus. Les thèmes s\'appliquent en direct, sans redémarrage. La langue est modifiable parmi 10 langues.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ thèmes','dd.gui.tag3':'10 langues','dd.gui.tag4':'thème en direct',
    'tech.tls.title':'TLS 1.2+ avec épinglage de certificat','tech.tls.p':'Authentification par clé partagée sur chaque paquet. Heartbeat 3s avec mesure RTT. Reconnexion automatique multi-hôte avec délai round-robin configurable.',
    'tech.ppid.title':'PPID spoofing dans RunPE','tech.ppid.p':'UpdateProcThreadAttribute définit le parent du processus injecté sur explorer.exe ou winlogon.exe selon le niveau d\'élévation.',
    'tech.wd.title':'Watchdog impossible à tuer','tech.wd.p':'4 processus gardiens dans dllhost/SearchProtocolHost avec PPID spoofing, décalés de 800ms. Verrou fichier + FileSystemWatcher pour restauration instantanée.',
    'feat.mon.1':'Bureau distant — DXGI + GDI fallback','feat.mon.2':'HVNC — bureau caché isolé','feat.mon.3':'Webcam — DirectShow + VFW','feat.mon.4':'Microphone — écoute en direct + sauvegarde WAV','feat.mon.5':'Keylogger — journalisation disque par date','feat.mon.6':'Moniteur de performances — CPU / RAM / Réseau','feat.mon.7':'Shell distant — cmd / PowerShell',
    'feat.adm.1':'Gestionnaire de fichiers — parcourir / télécharger / exécuter','feat.adm.2':'Gestionnaire de processus — vue arbre, icônes','feat.adm.3':'Éditeur de registre — HKLM + HKCU','feat.adm.4':'Gestionnaire de services / fenêtres / périphériques','feat.adm.5':'Connexions TCP + règles pare-feu','feat.adm.6':'Gestionnaire de démarrage','feat.adm.7':'Programmes installés — désinstallation silencieuse',
    'feat.off.1':'RunPE — en mémoire + PPID spoof','feat.off.2':'Proxy SOCKS5 inversé','feat.off.3':'Crypto Clipper — 10 cryptos','feat.off.4':'Plugins DLL AutoTask — C++, compilés à la demande','feat.off.5':'Mineur XMR — cible hollow configurable','feat.off.6':'Notification Telegram première exécution','feat.off.7':'Déduplication AutoTask par HWID','hero.features':'40+ fonctionnalités','footer.built':'Créé par ','footer.lic':' — utilisation autorisée uniquement.',
  },
  es: {
    'nav.features':'Funciones','nav.showcase':'Galería','nav.pricing':'Precios',
    'hero.eyebrow':'código abierto · solo uso autorizado',
    'hero.h1a':'El RAT/C2 que cobran','hero.h1b':'$2,000.','hero.h1c':'Gratis.',
    'hero.lead':'HVNC, escritorio remoto DXGI a 60fps, webcam vía DirectShow, process hollowing + PPID spoof, stub NativeAOT — más de 40 funciones. Todo lo que tienen los de pago. Sin el precio.',
    'hero.cta1':'Ver en GitHub','hero.cta2':'Capturas',
    's.features':'Lo que hace.',
    'col.mon':'Monitoreo','col.adm':'Administración','col.off':'Ofensivo',
    's.pricing':'El mercado.','s.pricing.sub':'Lo que otros cobran por lo mismo — a menudo peor, y código cerrado.',
    'price.closed':'comercial, código cerrado','price.leaked':'revertido y filtrado de todas formas','price.ours':'Fuente disponible, código completo en GitHub',
    's.showcase':'Capturas reales.','s.showcase.sub':'Sin demos fabricadas. Capturas reales del servidor.',
    's.tech':'Sin atajos.','s.tech.sub':'Los detalles que separan una demo de algo que desplegarías de verdad.',
    's.hvnc':'HVNC en acción.','s.hvnc.sub':'Demo en vivo — escritorio oculto, sesión navegador, control total. Sin edición.',
    's.contrib':'Colaboradores.','s.contrib.sub':'Las personas que lo construyeron.',
    'cta.h1':'Código abierto.','cta.h2':'Sin condiciones.',
    'cta.body':'Forkéalo. Constrúyelo. Hazlo tuyo. Solo úsalo en sistemas autorizados.',
    'cta.legal':'Solo para uso autorizado — red team, investigación de seguridad, CTF. Eres responsable de dónde lo apuntas.',
    'dd.hvnc.h3':'Computación de Red Virtual Oculta',
    'dd.hvnc.p1':'HVNC crea una sesión de escritorio Windows completamente aislada — invisible para el objetivo. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram y Explorer se lanzan directamente en la sesión sombra. La víctima no ve nada. Tú lo ves todo.',
    'dd.hvnc.p2a':'Cada navegador recibe ','dd.hvnc.p2b':' y llena el marco HVNC. Ratón y teclado transmitidos con precisión perfecta. Portapapeles sincronizado bajo demanda.',
    'dd.hvnc.tag1':'escritorio aislado','dd.hvnc.tag2':'11 apps','dd.hvnc.tag3':'sync portapapeles','dd.hvnc.tag4':'entrada en tiempo real',
    'dd.runpe.h3':'Vaciado de Proceso — RunPE x64',
    'dd.runpe.p1a':'No se crea ningún archivo nuevo — el PE existente se mapea vía ','dd.runpe.p1b':' en el objetivo vía ','dd.runpe.p1c':' — Windows resuelve reubicaciones e IAT automáticamente. El RIP del hilo se redirige al nuevo punto de entrada y se reanuda.',
    'dd.runpe.p2a':'PPID spoofing vía ','dd.runpe.p2b':' hace que el proceso inyectado aparezca como hijo de explorer.exe o winlogon.exe. Administrador de tareas, Process Explorer — sin nada sospechoso.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'sin escritura en disco','dd.runpe.tag3':'PPID spoof','dd.runpe.tag4':'creación suspendida','dd.runpe.tag5':'remap en memoria',
    'dd.gui.h3':'Interfaz WPF — DevExpress',
    'dd.gui.p1':'Construido sobre WPF con DevExpress 25.2. Navegación de barra lateral estilo NanoCore — un carril de iconos a la izquierda con paneles etiquetados por grupo de funciones. Toda la interfaz se adapta al tema activo en tiempo real.',
    'dd.gui.p2':'Un selector de temas integrado ofrece más de 20 ajustes — Sero Dark (predeterminado), DevExpress Dark, familia Office 2019, temas Visual Studio 2013, The Bezier, y más. Los temas se aplican en vivo sin reinicio. Idioma configurable en 10 idiomas.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ temas','dd.gui.tag3':'10 idiomas','dd.gui.tag4':'tema en vivo',
    'tech.tls.title':'TLS 1.2+ con fijación de certificado','tech.tls.p':'Autenticación por clave compartida en cada paquete. Heartbeat de 3s con medición RTT. Reconexión automática multi-host con retraso round-robin configurable.',
    'tech.ppid.title':'PPID spoofing en RunPE','tech.ppid.p':'UpdateProcThreadAttribute establece el proceso padre del proceso inyectado en explorer.exe o winlogon.exe según el nivel de elevación.',
    'tech.wd.title':'Watchdog que no se puede matar','tech.wd.p':'4 procesos guardianes en dllhost/SearchProtocolHost con PPID spoofing, escalonados 800ms. Bloqueo de archivos + FileSystemWatcher para restauración instantánea.',
    'feat.mon.1':'Escritorio remoto — DXGI + GDI fallback','feat.mon.2':'HVNC — escritorio oculto aislado','feat.mon.3':'Webcam — DirectShow + VFW','feat.mon.4':'Micrófono — escucha en vivo + guardar WAV','feat.mon.5':'Keylogger — registro en disco por fecha','feat.mon.6':'Monitor de rendimiento — CPU / RAM / Red','feat.mon.7':'Shell remoto — cmd / PowerShell',
    'feat.adm.1':'Gestor de archivos — navegar / subir / ejecutar','feat.adm.2':'Gestor de procesos — vista árbol, iconos','feat.adm.3':'Editor de registro — HKLM + HKCU','feat.adm.4':'Gestor de servicios / ventanas / dispositivos','feat.adm.5':'Conexiones TCP + reglas de firewall','feat.adm.6':'Gestor de inicio','feat.adm.7':'Programas instalados — desinstalación silenciosa',
    'feat.off.1':'RunPE — en memoria + PPID spoof','feat.off.2':'Proxy SOCKS5 inverso','feat.off.3':'Crypto Clipper — 10 criptomonedas','feat.off.4':'Plugins DLL AutoTask — C++, compilados bajo demanda','feat.off.5':'Minero XMR — objetivo hollow configurable','feat.off.6':'Notificación Telegram primera ejecución','feat.off.7':'Deduplicación AutoTask por HWID','hero.features':'40+ características','footer.built':'Creado por ','footer.lic':' — solo uso autorizado.',
  },
  de: {
    'nav.features':'Funktionen','nav.showcase':'Galerie','nav.pricing':'Preise',
    'hero.eyebrow':'Open Source · nur autorisierte Nutzung',
    'hero.h1a':'Das RAT/C2 für das','hero.h1b':'$2.000 verlangt werden.','hero.h1c':'Kostenlos.',
    'hero.lead':'HVNC, DXGI-Ferndesktop mit 60fps, Webcam via DirectShow, Process Hollowing + PPID-Spoofing, NativeAOT-Stub — 40+ Funktionen. Alles was die teuren haben. Ohne den Preisschild.',
    'hero.cta1':'Auf GitHub ansehen','hero.cta2':'Screenshots',
    's.features':'Was es kann.',
    'col.mon':'Überwachung','col.adm':'Verwaltung','col.off':'Offensiv',
    's.pricing':'Der Markt.','s.pricing.sub':'Was andere dafür verlangen — oft schlechter und nicht einsehbar.',
    'price.closed':'kommerziell, geschlossen','price.leaked':'sowieso reversed & geleakt','price.ours':'Quellcode verfügbar, vollständiger Code auf GitHub',
    's.showcase':'Echte Screenshots.','s.showcase.sub':'Keine gefakten Demos. Tatsächliche Aufnahmen vom Server.',
    's.tech':'Keine Abkürzungen.','s.tech.sub':'Die Details, die eine Demo von einem echten Deployment unterscheiden.',
    's.hvnc':'HVNC in Aktion.','s.hvnc.sub':'Live-Demo — versteckter Desktop, Browser-Sitzung, volle Kontrolle. Kein Schnitt.',
    's.contrib':'Mitwirkende.','s.contrib.sub':'Die Menschen, die das gebaut haben.',
    'cta.h1':'Open Source.','cta.h2':'Keine Bedingungen.',
    'cta.body':'Fork it. Bau darauf auf. Mach es zu deinem. Nur auf Systemen nutzen, für die du Genehmigung hast.',
    'cta.legal':'Nur für autorisierten Gebrauch — Red-Team, Sicherheitsforschung, CTF. Du trägst die Verantwortung.',
    'dd.hvnc.h3':'Verstecktes Virtuelles Netzwerk-Computing',
    'dd.hvnc.p1':'HVNC erstellt eine vollständig isolierte Windows-Desktop-Sitzung — für das Ziel unsichtbar. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram und Explorer starten direkt in der Schatten-Sitzung. Das Opfer sieht nichts. Du siehst alles.',
    'dd.hvnc.p2a':'Jeder Browser erhält ','dd.hvnc.p2b':' und füllt den HVNC-Rahmen. Maus und Tastatur pixelgenau weitergeleitet. Zwischenablage auf Abruf synchronisiert.',
    'dd.hvnc.tag1':'isolierter Desktop','dd.hvnc.tag2':'11 Apps','dd.hvnc.tag3':'Clipboard-Sync','dd.hvnc.tag4':'Echtzeiteingabe',
    'dd.runpe.h3':'Prozess-Hollowing — RunPE x64',
    'dd.runpe.p1a':'Keine neue Datei erstellt — die vorhandene PE wird via ','dd.runpe.p1b':' direkt in das Ziel eingeblendet via ','dd.runpe.p1c':' — Windows löst Relocations und IAT automatisch auf. Der Thread-RIP wird auf den neuen Eintrittspunkt umgeleitet und fortgesetzt.',
    'dd.runpe.p2a':'PPID-Spoofing via ','dd.runpe.p2b':' lässt den injizierten Prozess als Kind von explorer.exe oder winlogon.exe erscheinen. Task-Manager, Process Explorer — nichts Verdächtiges.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'kein Disk-Write','dd.runpe.tag3':'PPID-Spoof','dd.runpe.tag4':'suspended erstellt','dd.runpe.tag5':'Memory-Remap',
    'dd.gui.h3':'WPF-Oberfläche — DevExpress',
    'dd.gui.p1':'Aufgebaut auf WPF mit DevExpress 25.2. Sidebar-Navigation im NanoCore-Stil — eine Icon-Leiste links mit beschrifteten Panels für jede Funktionsgruppe. Die gesamte Oberfläche passt sich dem aktiven Theme in Echtzeit an.',
    'dd.gui.p2':'Ein eingebauter Theme-Picker bietet über 20 Voreinstellungen — Sero Dark (Standard), DevExpress Dark, Office-2019-Familie, Visual-Studio-2013-Themes, The Bezier und mehr. Themes werden sofort angewendet; kein Neustart nötig. Sprache in 10 Sprachen umschaltbar.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ Themes','dd.gui.tag3':'10 Sprachen','dd.gui.tag4':'Live-Theme-Wechsel',
    'tech.tls.title':'TLS 1.2+ mit Zertifikats-Pinning','tech.tls.p':'Shared-Key-Authentifizierung bei jedem Paket. 3s-Heartbeat mit RTT-Messung. Multi-Host-Wiederverbindung mit konfigurierbarer Round-Robin-Verzögerung.',
    'tech.ppid.title':'PPID-Spoofing in RunPE','tech.ppid.p':'UpdateProcThreadAttribute setzt den Elternprozess des injizierten Prozesses auf explorer.exe oder winlogon.exe je nach Erhebungsstufe.',
    'tech.wd.title':'Watchdog, der nicht getötet werden kann','tech.wd.p':'4 Wächterprozesse in dllhost/SearchProtocolHost mit PPID-Spoofing, gestaffelt 800ms. Datei-Lock + FileSystemWatcher für sofortige Wiederherstellung.',
    'feat.mon.1':'Ferndesktop — DXGI + GDI-Fallback','feat.mon.2':'HVNC — isolierter versteckter Desktop','feat.mon.3':'Webcam — DirectShow + VFW','feat.mon.4':'Mikrofon — Live-Hören + WAV-Speicherung','feat.mon.5':'Keylogger — Protokoll nach Datum','feat.mon.6':'Leistungsmonitor — CPU / RAM / Netz','feat.mon.7':'Remote-Shell — cmd / PowerShell',
    'feat.adm.1':'Datei-Manager — durchsuchen / hochladen / ausführen','feat.adm.2':'Prozess-Manager — Baumansicht, Icons','feat.adm.3':'Registrierungseditor — HKLM + HKCU','feat.adm.4':'Dienste / Fenster / Geräte-Manager','feat.adm.5':'TCP-Verbindungen + Firewall-Regeln','feat.adm.6':'Autostart-Manager','feat.adm.7':'Installierte Programme — stille Deinstallation',
    'feat.off.1':'RunPE — im Speicher + PPID-Spoof','feat.off.2':'Reverse-SOCKS5-Proxy','feat.off.3':'Crypto-Clipper — 10 Coins','feat.off.4':'AutoTask-DLL-Plugins — C++, on-demand kompiliert','feat.off.5':'XMR-Miner — konfigurierbares Hollow-Ziel','feat.off.6':'Telegram-Erstzugriff-Benachrichtigung','feat.off.7':'AutoTask-Deduplizierung per HWID','hero.features':'40+ Funktionen','footer.built':'Erstellt von ','footer.lic':' — nur autorisierte Nutzung.',
  },
  pt: {
    'nav.features':'Recursos','nav.showcase':'Galeria','nav.pricing':'Preços',
    'hero.eyebrow':'código aberto · apenas uso autorizado',
    'hero.h1a':'O RAT/C2 que cobram','hero.h1b':'$2.000.','hero.h1c':'Grátis.',
    'hero.lead':'HVNC, desktop remoto DXGI a 60fps, webcam via DirectShow, process hollowing + PPID spoof, stub NativeAOT — mais de 40 recursos. Tudo que os pagos têm. Sem o preço.',
    'hero.cta1':'Ver no GitHub','hero.cta2':'Screenshots',
    's.features':'O que faz.',
    'col.mon':'Monitoramento','col.adm':'Administração','col.off':'Ofensivo',
    's.pricing':'O mercado.','s.pricing.sub':'O que os outros cobram pela mesma coisa — geralmente pior, e código fechado.',
    'price.closed':'comercial, código fechado','price.leaked':'revertido e vazado de qualquer forma','price.ours':'Código disponível, completo no GitHub',
    's.showcase':'Screenshots reais.','s.showcase.sub':'Sem demos fabricadas. Capturas reais do servidor.',
    's.tech':'Sem atalhos.','s.tech.sub':'Os detalhes que separam uma demo de algo que você realmente implantaria.',
    's.hvnc':'HVNC em ação.','s.hvnc.sub':'Demo ao vivo — desktop oculto, sessão de navegador, controle total. Sem edição.',
    's.contrib':'Colaboradores.','s.contrib.sub':'As pessoas que construíram isso.',
    'cta.h1':'Código aberto.','cta.h2':'Sem condições.',
    'cta.body':'Fork it. Construa em cima. Faça seu. Use apenas em sistemas que você tem autorização.',
    'cta.legal':'Apenas para uso autorizado — red team, pesquisa de segurança, CTF. Você é responsável pelo uso.',
    'dd.hvnc.h3':'Computação em Rede Virtual Oculta',
    'dd.hvnc.p1':'HVNC cria uma sessão de desktop Windows completamente isolada — invisível para o alvo. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram e Explorer são iniciados diretamente na sessão sombra. A vítima não vê nada. Você vê tudo.',
    'dd.hvnc.p2a':'Cada navegador recebe ','dd.hvnc.p2b':' e preenche o quadro HVNC. Mouse e teclado transmitidos com precisão perfeita. Área de transferência sincronizada sob demanda.',
    'dd.hvnc.tag1':'desktop isolado','dd.hvnc.tag2':'11 apps','dd.hvnc.tag3':'sync clipboard','dd.hvnc.tag4':'entrada em tempo real',
    'dd.runpe.h3':'Process Hollowing — RunPE x64',
    'dd.runpe.p1a':'Nenhum arquivo novo criado — o PE existente é mapeado via ','dd.runpe.p1b':' no alvo via ','dd.runpe.p1c':' — Windows resolve relocações e IAT automaticamente. O RIP da thread é redirecionado para o novo ponto de entrada e retomado.',
    'dd.runpe.p2a':'PPID spoofing via ','dd.runpe.p2b':' faz o processo injetado aparecer como filho de explorer.exe ou winlogon.exe. Gerenciador de Tarefas, Process Explorer — nada suspeito.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'sem escrita em disco','dd.runpe.tag3':'PPID spoof','dd.runpe.tag4':'criação suspensa','dd.runpe.tag5':'remap em memória',
    'dd.gui.h3':'Interface WPF — DevExpress',
    'dd.gui.p1':'Construído sobre WPF com DevExpress 25.2. Navegação em barra lateral no estilo NanoCore — uma trilha de ícones à esquerda com painéis rotulados por grupo de funcionalidades. Toda a interface se adapta ao tema ativo em tempo real.',
    'dd.gui.p2':'Um seletor de temas integrado oferece mais de 20 predefinições — Sero Dark (padrão), DevExpress Dark, família Office 2019, temas Visual Studio 2013, The Bezier e mais. Temas aplicados ao vivo sem reinicialização. Idioma configurável em 10 idiomas.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ temas','dd.gui.tag3':'10 idiomas','dd.gui.tag4':'troca de tema ao vivo',
    'tech.tls.title':'TLS 1.2+ com fixação de certificado','tech.tls.p':'Autenticação por chave compartilhada em cada pacote. Heartbeat de 3s com medição RTT. Reconexão automática multi-host com atraso round-robin configurável.',
    'tech.ppid.title':'PPID spoofing no RunPE','tech.ppid.p':'UpdateProcThreadAttribute define o processo pai do processo injetado como explorer.exe ou winlogon.exe dependendo do nível de elevação.',
    'tech.wd.title':'Watchdog que não pode ser morto','tech.wd.p':'4 processos guardiões em dllhost/SearchProtocolHost com PPID spoofing, defasados 800ms. File lock + FileSystemWatcher para restauração instantânea.',
    'feat.mon.1':'Desktop remoto — DXGI + fallback GDI','feat.mon.2':'HVNC — desktop oculto isolado','feat.mon.3':'Webcam — DirectShow + VFW','feat.mon.4':'Microfone — escuta ao vivo + salvar WAV','feat.mon.5':'Keylogger — log em disco por data','feat.mon.6':'Monitor de desempenho — CPU / RAM / Rede','feat.mon.7':'Shell remoto — cmd / PowerShell',
    'feat.adm.1':'Gerenciador de arquivos — navegar / enviar / executar','feat.adm.2':'Gerenciador de processos — visão em árvore, ícones','feat.adm.3':'Editor de registro — HKLM + HKCU','feat.adm.4':'Gerenciador de serviços / janelas / dispositivos','feat.adm.5':'Conexões TCP + regras de firewall','feat.adm.6':'Gerenciador de inicialização','feat.adm.7':'Programas instalados — desinstalação silenciosa',
    'feat.off.1':'RunPE — em memória + PPID spoof','feat.off.2':'Proxy SOCKS5 reverso','feat.off.3':'Crypto Clipper — 10 moedas','feat.off.4':'Plugins DLL AutoTask — C++, compilados sob demanda','feat.off.5':'Minerador XMR — alvo hollow configurável','feat.off.6':'Notificação Telegram na primeira execução','feat.off.7':'Deduplicação AutoTask por HWID','hero.features':'40+ funcionalidades','footer.built':'Criado por ','footer.lic':' — apenas uso autorizado.',
  },
  ru: {
    'nav.features':'Функции','nav.showcase':'Галерея','nav.pricing':'Цены',
    'hero.eyebrow':'открытый код · только авторизованное использование',
    'hero.h1a':'RAT/C2, за который берут','hero.h1b':'$2 000.','hero.h1c':'Бесплатно.',
    'hero.lead':'HVNC, удалённый рабочий стол DXGI 60fps, веб-камера через DirectShow, process hollowing + PPID spoof, стаб NativeAOT — 40+ функций. Всё, что есть у платных. Без ценника.',
    'hero.cta1':'Смотреть на GitHub','hero.cta2':'Скриншоты',
    's.features':'Что умеет.',
    'col.mon':'Мониторинг','col.adm':'Администрирование','col.off':'Атака',
    's.pricing':'Рынок.','s.pricing.sub':'Что другие берут за то же самое — зачастую хуже и с закрытым кодом.',
    'price.closed':'коммерческий, закрытый код','price.leaked':'в итоге всё равно утёк','price.ours':'Исходный код доступен, полный код на GitHub',
    's.showcase':'Реальные скриншоты.','s.showcase.sub':'Без постановочных демо. Реальные снимки с сервера.',
    's.tech':'Без компромиссов.','s.tech.sub':'Детали, которые отличают демо от реального инструмента.',
    's.hvnc':'HVNC в действии.','s.hvnc.sub':'Живое демо — скрытый рабочий стол, сессия браузера, полный контроль. Без монтажа.',
    's.contrib':'Участники.','s.contrib.sub':'Люди, которые это построили.',
    'cta.h1':'Открытый код.','cta.h2':'Без условий.',
    'cta.body':'Форкайте. Стройте на его основе. Делайте своим. Используйте только на разрешённых системах.',
    'cta.legal':'Только для авторизованного использования — red team, исследование безопасности, CTF.',
    'dd.hvnc.h3':'Скрытые Виртуальные Вычисления',
    'dd.hvnc.p1':'HVNC создаёт полностью изолированный сеанс рабочего стола Windows — невидимый для цели. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram и Explorer запускаются прямо в теневом сеансе. Жертва ничего не видит. Вы видите всё.',
    'dd.hvnc.p2a':'Каждый браузер получает ','dd.hvnc.p2b':' и заполняет кадр HVNC. Мышь и клавиатура пересылаются с пиксельной точностью. Буфер обмена синхронизируется по запросу.',
    'dd.hvnc.tag1':'изолированный стол','dd.hvnc.tag2':'11 приложений','dd.hvnc.tag3':'синхронизация буфера','dd.hvnc.tag4':'ввод в реальном времени',
    'dd.runpe.h3':'Hollowing Процесса — RunPE x64',
    'dd.runpe.p1a':'Новый файл не создаётся — существующий PE маппится через ','dd.runpe.p1b':' в целевой процесс через ','dd.runpe.p1c':' — Windows автоматически разрешает релокации и IAT. RIP потока перенаправляется на новую точку входа и возобновляется.',
    'dd.runpe.p2a':'PPID-спуфинг через ','dd.runpe.p2b':' делает инжектированный процесс дочерним к explorer.exe или winlogon.exe. Диспетчер задач, Process Explorer — ничего подозрительного.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'без записи на диск','dd.runpe.tag3':'PPID-спуфинг','dd.runpe.tag4':'создание в паузе','dd.runpe.tag5':'ремап памяти',
    'dd.gui.h3':'Интерфейс WPF — DevExpress',
    'dd.gui.p1':'Построен на WPF с DevExpress 25.2. Навигация через боковую панель в стиле NanoCore — рейка иконок слева с подписанными панелями для каждой группы функций. Весь интерфейс адаптируется к активной теме в реальном времени.',
    'dd.gui.p2':'Встроенный выбор тем предлагает более 20 пресетов — Sero Dark (по умолчанию), DevExpress Dark, семейство Office 2019, темы Visual Studio 2013, The Bezier и другие. Темы применяются мгновенно без перезапуска. Язык интерфейса переключается среди 10 языков.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ тем','dd.gui.tag3':'10 языков','dd.gui.tag4':'смена темы вживую',
    'tech.tls.title':'TLS 1.2+ с закреплением сертификата','tech.tls.p':'Аутентификация по общему ключу в каждом пакете. Heartbeat 3s с измерением RTT. Автоматическое переподключение к нескольким хостам с настраиваемой задержкой round-robin.',
    'tech.ppid.title':'PPID-спуфинг в RunPE','tech.ppid.p':'UpdateProcThreadAttribute устанавливает родительский процесс инжектированного процесса как explorer.exe или winlogon.exe в зависимости от уровня привилегий.',
    'tech.wd.title':'Watchdog, который невозможно убить','tech.wd.p':'4 процесса-стража в dllhost/SearchProtocolHost с PPID-спуфингом, интервал 800ms. Блокировка файла + FileSystemWatcher для мгновенного восстановления.',
    'feat.mon.1':'Удалённый рабочий стол — DXGI + GDI fallback','feat.mon.2':'HVNC — изолированный скрытый рабочий стол','feat.mon.3':'Веб-камера — DirectShow + VFW','feat.mon.4':'Микрофон — прослушка в реальном времени + сохранение WAV','feat.mon.5':'Кейлоггер — журнал на диске по дате','feat.mon.6':'Монитор производительности — CPU / ОЗУ / Сеть','feat.mon.7':'Удалённая оболочка — cmd / PowerShell',
    'feat.adm.1':'Файловый менеджер — обзор / загрузка / выполнение','feat.adm.2':'Менеджер процессов — дерево, иконки','feat.adm.3':'Редактор реестра — HKLM + HKCU','feat.adm.4':'Менеджер служб / окон / устройств','feat.adm.5':'TCP-соединения + правила брандмауэра','feat.adm.6':'Менеджер автозагрузки','feat.adm.7':'Установленные программы — тихое удаление',
    'feat.off.1':'RunPE — в памяти + PPID-спуф','feat.off.2':'Обратный прокси SOCKS5','feat.off.3':'Crypto Clipper — 10 монет','feat.off.4':'Плагины AutoTask DLL — C++, компилируются по запросу','feat.off.5':'Майнер XMR — настраиваемая цель','feat.off.6':'Уведомление в Telegram при первом запуске','feat.off.7':'Дедупликация AutoTask по HWID','hero.features':'40+ функций','footer.built':'Создано ','footer.lic':' — только авторизованное использование.',
  },
  zh: {
    'nav.features':'功能','nav.showcase':'展示','nav.pricing':'价格',
    'hero.eyebrow':'开源 · 仅限授权使用',
    'hero.h1a':'同类工具收费','hero.h1b':'$2,000 的 RAT/C2。','hero.h1c':'免费。',
    'hero.lead':'HVNC、DXGI 60fps 远程桌面、DirectShow 网络摄像头、进程镂空 + PPID 欺骗、NativeAOT 存根 — 40+ 功能。付费工具有的全都有，没有价格标签。',
    'hero.cta1':'在 GitHub 查看','hero.cta2':'截图',
    's.features':'功能列表。',
    'col.mon':'监控','col.adm':'管理','col.off':'攻击',
    's.pricing':'市场行情。','s.pricing.sub':'同类工具的收费情况 — 功能往往更差，且代码闭源。',
    'price.closed':'商业版，闭源','price.leaked':'已被逆向并泄露','price.ours':'源码可用，完整源码在 GitHub',
    's.showcase':'真实截图。','s.showcase.sub':'没有虚构的演示。全是服务器的实际截图。',
    's.tech':'没有捷径。','s.tech.sub':'区别演示和真正可部署工具的技术细节。',
    's.hvnc':'HVNC 实战。','s.hvnc.sub':'实时演示 — 隐藏桌面、浏览器会话、完全控制。未经剪辑。',
    's.contrib':'贡献者。','s.contrib.sub':'构建这个工具的人。',
    'cta.h1':'开源。','cta.h2':'无附加条件。',
    'cta.body':'Fork 它。在上面构建。据为己有。只在有授权的系统上使用。',
    'cta.legal':'仅用于授权用途 — 红队演练、安全研究、CTF。您对自己的使用行为负责。',
    'dd.hvnc.h3':'隐藏虚拟网络计算',
    'dd.hvnc.p1':'HVNC 创建完全隔离的 Windows 桌面会话 — 对目标不可见。Chrome、Edge、Firefox、Brave、Vivaldi、Opera、Opera GX、Telegram、Discord、AyuGram 和 Explorer 直接在影子会话中启动。受害者什么都看不到。你看到一切。',
    'dd.hvnc.p2a':'每个浏览器均带有 ','dd.hvnc.p2b':'，填满 HVNC 画面。鼠标和键盘以像素精度转发。剪贴板按需同步。',
    'dd.hvnc.tag1':'隔离桌面','dd.hvnc.tag2':'11 个应用','dd.hvnc.tag3':'剪贴板同步','dd.hvnc.tag4':'实时输入',
    'dd.runpe.h3':'进程镂空 — RunPE x64',
    'dd.runpe.p1a':'不创建新文件 — 现有 PE 通过 ','dd.runpe.p1b':' 映射到目标进程，经由 ','dd.runpe.p1c':' — Windows 自动解析重定位和 IAT。线程 RIP 被重定向到新入口点，然后恢复执行。',
    'dd.runpe.p2a':'通过 ','dd.runpe.p2b':' 的 PPID 欺骗使注入进程显示为 explorer.exe 或 winlogon.exe 的子进程。任务管理器、Process Explorer — 看不到任何可疑内容。',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'不写入磁盘','dd.runpe.tag3':'PPID 欺骗','dd.runpe.tag4':'挂起创建','dd.runpe.tag5':'内存重映射',
    'dd.gui.h3':'WPF 界面 — DevExpress',
    'dd.gui.p1':'基于 WPF 与 DevExpress 25.2 构建。侧边栏导航采用 NanoCore 风格 — 左侧图标栏搭配各功能组的标签面板。整个界面实时响应当前主题。',
    'dd.gui.p2':'内置主题选择器提供 20+ 个预设 — 包括 Sero Dark（默认）、DevExpress Dark、Office 2019 系列、Visual Studio 2013 主题、The Bezier 等。主题即时切换，无需重启。界面语言支持 10 种语言。',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ 主题','dd.gui.tag3':'10 种语言','dd.gui.tag4':'实时切换主题',
    'tech.tls.title':'TLS 1.2+ 证书锁定','tech.tls.p':'每个数据包均进行共享密钥验证。3 秒心跳包含 RTT 测量。支持多主机自动重连，具有可配置的轮询延迟。',
    'tech.ppid.title':'RunPE 中的 PPID 欺骗','tech.ppid.p':'UpdateProcThreadAttribute 根据提权级别将注入进程的父进程设置为 explorer.exe 或 winlogon.exe。',
    'tech.wd.title':'无法被终止的 Watchdog','tech.wd.p':'在 dllhost/SearchProtocolHost 中有 4 个守护进程，使用 PPID 欺骗，间隔 800ms 交错启动。文件锁 + FileSystemWatcher 实现即时恢复。',
    'feat.mon.1':'远程桌面 — DXGI + GDI 回退','feat.mon.2':'HVNC — 隔离的隐藏桌面','feat.mon.3':'摄像头 — DirectShow + VFW','feat.mon.4':'麦克风 — 实时监听 + WAV 保存','feat.mon.5':'键盘记录器 — 按日期记录到磁盘','feat.mon.6':'性能监控 — CPU / 内存 / 网络','feat.mon.7':'远程 Shell — cmd / PowerShell',
    'feat.adm.1':'文件管理器 — 浏览 / 上传 / 执行','feat.adm.2':'进程管理器 — 树形视图，图标','feat.adm.3':'注册表编辑器 — HKLM + HKCU','feat.adm.4':'服务 / 窗口 / 设备管理器','feat.adm.5':'TCP 连接 + 防火墙规则','feat.adm.6':'启动项管理器','feat.adm.7':'已安装程序 — 静默卸载',
    'feat.off.1':'RunPE — 内存 + PPID 欺骗','feat.off.2':'反向 SOCKS5 代理','feat.off.3':'加密剪切板劫持 — 10 种币','feat.off.4':'AutoTask DLL 插件 — C++，按需编译','feat.off.5':'XMR 挖矿 — 可配置镂空目标','feat.off.6':'Telegram 首次执行通知','feat.off.7':'按 HWID 的 AutoTask 去重','hero.features':'40+ 功能','footer.built':'作者：','footer.lic':'— 仅授权使用。',
  },
  ja: {
    'nav.features':'機能','nav.showcase':'ギャラリー','nav.pricing':'価格',
    'hero.eyebrow':'オープンソース · 認可された使用のみ',
    'hero.h1a':'他が$2,000で売る','hero.h1b':'RAT/C2。','hero.h1c':'無料。',
    'hero.lead':'HVNC、60fps DXGI リモートデスクトップ、DirectShow ウェブカメラ、プロセスホロウイング + PPIDスプーフ、NativeAOTスタブ — 40以上の機能。高価なツールが持つすべて。価格タグなし。',
    'hero.cta1':'GitHubで見る','hero.cta2':'スクリーンショット',
    's.features':'機能一覧。',
    'col.mon':'モニタリング','col.adm':'管理','col.off':'攻撃',
    's.pricing':'市場価格。','s.pricing.sub':'他社が同じものに課金する金額 — 多くは機能が劣り、ソースも非公開。',
    'price.closed':'商用、クローズドソース','price.leaked':'リバースされ流出済み','price.ours':'ソース公開、GitHubに全コード',
    's.showcase':'実際のスクリーンショット。','s.showcase.sub':'作られたデモなし。サーバーからの実際のキャプチャ。',
    's.tech':'近道なし。','s.tech.sub':'デモと実際にデプロイできるものを分ける技術的詳細。',
    's.hvnc':'HVNCの実演。','s.hvnc.sub':'ライブデモ — 隠しデスクトップ、ブラウザセッション、フルコントロール。編集なし。',
    's.contrib':'貢献者。','s.contrib.sub':'これを作った人々。',
    'cta.h1':'オープンソース。','cta.h2':'条件なし。',
    'cta.body':'フォークして。その上に構築して。あなたのものにして。許可されたシステムでのみ使用してください。',
    'cta.legal':'認可された使用のみ — レッドチーム、セキュリティ研究、CTF。',
    'dd.hvnc.h3':'隠しバーチャルネットワークコンピューティング',
    'dd.hvnc.p1':'HVNCは完全に隔離されたWindowsデスクトップセッションを作成します — ターゲットには見えません。Chrome、Edge、Firefox、Brave、Vivaldi、Opera、Opera GX、Telegram、Discord、AyuGram、Explorerがシャドウセッションに直接起動します。被害者は何も見えません。あなたはすべてを見ます。',
    'dd.hvnc.p2a':'各ブラウザは ','dd.hvnc.p2b':' でHVNCフレームを埋めます。マウスとキーボードはピクセル精度で転送。クリップボードはオンデマンドで同期されます。',
    'dd.hvnc.tag1':'隔離デスクトップ','dd.hvnc.tag2':'11アプリ','dd.hvnc.tag3':'クリップボード同期','dd.hvnc.tag4':'リアルタイム入力',
    'dd.runpe.h3':'プロセスホロウイング — RunPE x64',
    'dd.runpe.p1a':'新しいファイルは作成されません — 既存のPEが ','dd.runpe.p1b':' を通じてターゲットに直接マップされます — ','dd.runpe.p1c':' — Windowsが再配置とIATを自動解決。スレッドのRIPが新しいエントリポイントにリダイレクトされ、再開されます。',
    'dd.runpe.p2a':'PPIDスプーフィング（','dd.runpe.p2b':'）によって注入プロセスがexplorer.exeまたはwinlogon.exeの子として表示されます。タスクマネージャー、Process Explorer — 不審なものはありません。',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'ディスク書込なし','dd.runpe.tag3':'PPIDスプーフ','dd.runpe.tag4':'サスペンド起動','dd.runpe.tag5':'メモリリマップ',
    'dd.gui.h3':'WPF インターフェース — DevExpress',
    'dd.gui.p1':'WPF と DevExpress 25.2 で構築。NanoCore スタイルのサイドバーナビゲーション — 左側のアイコンレールと各機能グループのラベル付きパネル。UI 全体がアクティブなテーマにリアルタイムで適応します。',
    'dd.gui.p2':'内蔵テーマピッカーが 20 以上のプリセットを提供 — Sero Dark（デフォルト）、DevExpress Dark、Office 2019 ファミリー、Visual Studio 2013 テーマ、The Bezier など。テーマは再起動不要でライブ適用。インターフェース言語は 10 言語対応。',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ テーマ','dd.gui.tag3':'10 言語','dd.gui.tag4':'ライブテーマ切替',
    'tech.tls.title':'TLS 1.2+ 証明書ピニング','tech.tls.p':'すべてのパケットに共有鍵認証。RTT測定付き3秒ハートビート。設定可能なラウンドロビン遅延によるマルチホスト自動再接続。',
    'tech.ppid.title':'RunPEのPPIDスプーフィング','tech.ppid.p':'UpdateProcThreadAttributeが昇格レベルに応じてexplorer.exeまたはwinlogon.exeを注入プロセスの親として設定します。',
    'tech.wd.title':'終了できないWatchdog','tech.wd.p':'dllhost/SearchProtocolHostで800ms間隔でPPIDスプーフィングした4つのガードプロセス。ファイルロック + FileSystemWatcherで即時復元。',
    'feat.mon.1':'リモートデスクトップ — DXGI + GDIフォールバック','feat.mon.2':'HVNC — 隔離された隠しデスクトップ','feat.mon.3':'ウェブカメラ — DirectShow + VFW','feat.mon.4':'マイク — ライブリスニング + WAV保存','feat.mon.5':'キーロガー — 日付別ディスクログ','feat.mon.6':'パフォーマンスモニター — CPU / RAM / ネット','feat.mon.7':'リモートシェル — cmd / PowerShell',
    'feat.adm.1':'ファイルマネージャー — 参照 / アップロード / 実行','feat.adm.2':'プロセスマネージャー — ツリービュー、アイコン','feat.adm.3':'レジストリエディター — HKLM + HKCU','feat.adm.4':'サービス / ウィンドウ / デバイスマネージャー','feat.adm.5':'TCP接続 + ファイアウォールルール','feat.adm.6':'スタートアップマネージャー','feat.adm.7':'インストール済みプログラム — サイレントアンインストール',
    'feat.off.1':'RunPE — メモリ内 + PPIDスプーフ','feat.off.2':'リバースSOCKS5プロキシ','feat.off.3':'暗号クリッパー — 10コイン','feat.off.4':'AutoTask DLLプラグイン — C++、オンデマンドコンパイル','feat.off.5':'XMRマイナー — 設定可能なホローターゲット','feat.off.6':'Telegram初回実行通知','feat.off.7':'HWIDによるAutoTask重複排除','hero.features':'40+ 機能','footer.built':'作者：','footer.lic':'— 認可使用のみ。',
  },
  ar: {
    'nav.features':'المميزات','nav.showcase':'معرض','nav.pricing':'الأسعار',
    'hero.eyebrow':'مفتوح المصدر · للاستخدام المرخص فقط',
    'hero.h1a':'الـ RAT/C2 الذي يبيعونه بـ','hero.h1b':'ألفي دولار.','hero.h1c':'مجاناً.',
    'hero.lead':'HVNC، سطح مكتب بعيد DXGI بـ 60fps، كاميرا ويب عبر DirectShow، حقن العمليات + PPID Spoof، stub NativeAOT — أكثر من 40 ميزة. كل ما لدى الأدوات المدفوعة. بدون سعر.',
    'hero.cta1':'عرض على GitHub','hero.cta2':'لقطات الشاشة',
    's.features':'ما يفعله.',
    'col.mon':'مراقبة','col.adm':'إدارة','col.off':'هجومي',
    's.pricing':'السوق.','s.pricing.sub':'ما يفرضه الآخرون على نفس الشيء — في الغالب أسوأ، ومغلق المصدر.',
    'price.closed':'تجاري، مغلق المصدر','price.leaked':'تم عكسه وتسريبه على أي حال','price.ours':'المصدر متاح، الكود الكامل على GitHub',
    's.showcase':'لقطات حقيقية.','s.showcase.sub':'لا عروض مزيفة. لقطات فعلية من الخادم.',
    's.tech':'لا اختصارات.','s.tech.sub':'التفاصيل التي تفرق بين العرض التوضيحي وشيء ستنشره فعلاً.',
    's.hvnc':'HVNC في العمل.','s.hvnc.sub':'عرض حي — سطح مكتب خفي، جلسة متصفح، تحكم كامل. بدون تعديل.',
    's.contrib':'المساهمون.','s.contrib.sub':'الأشخاص الذين بنوا هذا.',
    'cta.h1':'مفتوح المصدر.','cta.h2':'بلا قيود.',
    'cta.body':'قم بعمل Fork. ابنِ عليه. اجعله ملكك. استخدمه فقط على الأنظمة التي لديك تفويض لها.',
    'cta.legal':'للاستخدام المرخص فقط — اختبارات الفريق الأحمر، أبحاث الأمن، CTF.',
    'dd.hvnc.h3':'الحوسبة عبر الشبكة الافتراضية المخفية',
    'dd.hvnc.p1':'يُنشئ HVNC جلسة سطح مكتب Windows معزولة تمامًا — غير مرئية للهدف. يُطلق Chrome وEdge وFirefox وBrave وVivaldi وOpera وOpera GX وTelegram وDiscord وAyuGram وExplorer مباشرةً في الجلسة الظلية. الضحية لا ترى شيئًا. أنت ترى كل شيء.',
    'dd.hvnc.p2a':'يحصل كل متصفح على ','dd.hvnc.p2b':' ويملأ إطار HVNC. يُعاد توجيه الماوس ولوحة المفاتيح بدقة البكسل. الحافظة مزامنة عند الطلب.',
    'dd.hvnc.tag1':'سطح مكتب معزول','dd.hvnc.tag2':'11 تطبيق','dd.hvnc.tag3':'مزامنة الحافظة','dd.hvnc.tag4':'إدخال فوري',
    'dd.runpe.h3':'تجويف العملية — RunPE x64',
    'dd.runpe.p1a':'لا يُنشأ أي ملف جديد — يُعيَّن PE الموجود عبر ','dd.runpe.p1b':' مباشرةً في الهدف عبر ','dd.runpe.p1c':' — يحل Windows عمليات الانتقال وجدول IAT تلقائيًا. يُعاد توجيه RIP الخيط إلى نقطة الدخول الجديدة ثم يُستأنف.',
    'dd.runpe.p2a':'انتحال PPID عبر ','dd.runpe.p2b':' يجعل العملية المُحقنة تظهر كابن لـ explorer.exe أو winlogon.exe. إدارة المهام، Process Explorer — لا شيء مريب.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'بدون كتابة للقرص','dd.runpe.tag3':'انتحال PPID','dd.runpe.tag4':'إنشاء معلّق','dd.runpe.tag5':'إعادة تعيين الذاكرة',
    'dd.gui.h3':'واجهة WPF — DevExpress',
    'dd.gui.p1':'مبني على WPF مع DevExpress 25.2. تنقل الشريط الجانبي بأسلوب NanoCore — شريط أيقونات على اليسار مع لوحات موسومة لكل مجموعة ميزات. تتكيف الواجهة بالكامل مع الثيم النشط في الوقت الفعلي.',
    'dd.gui.p2':'منتقي الثيمات المدمج يوفر أكثر من 20 إعداداً مسبقاً — Sero Dark (الافتراضي) وDevExpress Dark وعائلة Office 2019 وثيمات Visual Studio 2013 وThe Bezier والمزيد. تُطبَّق الثيمات فوراً دون إعادة تشغيل. لغة الواجهة قابلة للتبديل بين 10 لغات.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'أكثر من 20 ثيماً','dd.gui.tag3':'10 لغات','dd.gui.tag4':'تبديل ثيم مباشر',
    'tech.tls.title':'TLS 1.2+ مع تثبيت الشهادة','tech.tls.p':'مصادقة بمفتاح مشترك على كل حزمة. نبضة قلب 3 ثوانٍ مع قياس RTT. إعادة اتصال تلقائي متعدد المضيفين مع تأخير round-robin قابل للضبط.',
    'tech.ppid.title':'انتحال PPID في RunPE','tech.ppid.p':'يعيّن UpdateProcThreadAttribute العملية الأم للعملية المُحقنة إلى explorer.exe أو winlogon.exe حسب مستوى الامتيازات.',
    'tech.wd.title':'Watchdog لا يمكن إيقافه','tech.wd.p':'4 عمليات حارسة في dllhost/SearchProtocolHost مع انتحال PPID، بفارق 800ms. قفل الملف + FileSystemWatcher للاستعادة الفورية.',
    'feat.mon.1':'سطح المكتب البعيد — DXGI + GDI احتياطي','feat.mon.2':'HVNC — سطح مكتب خفي معزول','feat.mon.3':'كاميرا الويب — DirectShow + VFW','feat.mon.4':'الميكروفون — استماع مباشر + حفظ WAV','feat.mon.5':'مسجل المفاتيح — تسجيل يومي على القرص','feat.mon.6':'مراقب الأداء — CPU / RAM / الشبكة','feat.mon.7':'Shell بعيد — cmd / PowerShell',
    'feat.adm.1':'مدير الملفات — تصفح / رفع / تنفيذ','feat.adm.2':'مدير العمليات — عرض شجري، أيقونات','feat.adm.3':'محرر السجل — HKLM + HKCU','feat.adm.4':'مدير الخدمات / النوافذ / الأجهزة','feat.adm.5':'اتصالات TCP + قواعد جدار الحماية','feat.adm.6':'مدير بدء التشغيل','feat.adm.7':'البرامج المثبتة — إزالة تثبيت صامتة',
    'feat.off.1':'RunPE — في الذاكرة + PPID spoof','feat.off.2':'بروكسي SOCKS5 عكسي','feat.off.3':'Crypto Clipper — 10 عملات','feat.off.4':'مكونات AutoTask DLL — C++، يُجمَّع عند الطلب','feat.off.5':'مُعدِّن XMR — هدف hollow قابل للضبط','feat.off.6':'إشعار Telegram عند أول تشغيل','feat.off.7':'إزالة تكرار AutoTask بواسطة HWID','hero.features':'+40 ميزة','footer.built':'بناء بواسطة ','footer.lic':' — للاستخدام المرخص فقط.',
  },
  it: {
    'nav.features':'Funzionalità','nav.showcase':'Galleria','nav.pricing':'Prezzi',
    'hero.eyebrow':'open source · solo uso autorizzato',
    'hero.h1a':'Il RAT/C2 che vendono a','hero.h1b':'$2.000.','hero.h1c':'Gratis.',
    'hero.lead':'HVNC, desktop remoto DXGI a 60fps, webcam remota via DirectShow, process hollowing + PPID spoof, stub NativeAOT — oltre 40 funzionalità. Tutto quello che hanno i tool a pagamento. Senza il cartellino del prezzo.',
    'hero.cta1':'Guarda su GitHub','hero.cta2':'Screenshot',
    's.features':'Cosa fa.',
    'col.mon':'Monitoraggio','col.adm':'Amministrazione','col.off':'Offensivo',
    's.pricing':'Il mercato.','s.pricing.sub':'Quanto chiedono gli altri per la stessa cosa — spesso peggiori e codice chiuso.',
    'price.closed':'commerciale, codice chiuso','price.leaked':'rivertito e leakato comunque','price.ours':'Sorgente disponibile, codice completo su GitHub',
    's.showcase':'Screenshot reali.','s.showcase.sub':'Nessuna demo costruita. Catture reali dal server.',
    's.tech':'Nessuna scorciatoia.','s.tech.sub':'I dettagli che separano una demo da qualcosa che vorresti davvero deployare.',
    's.hvnc':'HVNC in azione.','s.hvnc.sub':'Demo live — desktop nascosto, sessione browser, pieno controllo. Senza montaggio.',
    's.contrib':'Contributori.','s.contrib.sub':'Le persone che lo hanno costruito.',
    'cta.h1':'Open source.','cta.h2':'Senza condizioni.',
    'cta.body':'Fai il fork. Costruisci sopra. Fallo tuo. Usalo solo su sistemi per cui hai autorizzazione.',
    'cta.legal':'Solo per uso autorizzato — red team, ricerca sulla sicurezza, CTF.',
    'dd.hvnc.h3':'Rete di Calcolo Virtuale Nascosta',
    'dd.hvnc.p1':'HVNC crea una sessione desktop Windows completamente isolata — invisibile al bersaglio. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram e Explorer si avviano direttamente nella sessione ombra. La vittima non vede nulla. Tu vedi tutto.',
    'dd.hvnc.p2a':'Ogni browser riceve ','dd.hvnc.p2b':' e riempie il frame HVNC. Mouse e tastiera inoltrati con precisione pixel-perfect. Appunti sincronizzati su richiesta.',
    'dd.hvnc.tag1':'desktop isolato','dd.hvnc.tag2':'11 app','dd.hvnc.tag3':'sync appunti','dd.hvnc.tag4':'input in tempo reale',
    'dd.runpe.h3':'Svuotamento Processo — RunPE x64',
    'dd.runpe.p1a':'Nessun nuovo file creato — il PE esistente viene mappato via ','dd.runpe.p1b':' nel target via ','dd.runpe.p1c':' — Windows risolve automaticamente le rilocazioni e l\'IAT. Il RIP del thread è reindirizzato al nuovo punto di ingresso, quindi ripreso.',
    'dd.runpe.p2a':'Il PPID spoofing via ','dd.runpe.p2b':' fa apparire il processo iniettato come figlio di explorer.exe o winlogon.exe. Task Manager, Process Explorer — niente di sospetto.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'nessuna scrittura su disco','dd.runpe.tag3':'PPID spoof','dd.runpe.tag4':'creazione sospesa','dd.runpe.tag5':'remap memoria',
    'dd.gui.h3':'Interfaccia WPF — DevExpress',
    'dd.gui.p1':'Costruita su WPF con DevExpress 25.2. Navigazione a barra laterale in stile NanoCore — una barra di icone a sinistra con pannelli etichettati per ogni gruppo di funzionalità. L\'intera interfaccia si adatta al tema attivo in tempo reale.',
    'dd.gui.p2':'Un selettore temi integrato offre oltre 20 preset — Sero Dark (predefinito), DevExpress Dark, famiglia Office 2019, temi Visual Studio 2013, The Bezier e altro. I temi si applicano in diretta senza riavvio. La lingua è selezionabile tra 10 localizzazioni.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ temi','dd.gui.tag3':'10 lingue','dd.gui.tag4':'tema in diretta',
    'tech.tls.title':'TLS 1.2+ con certificate pinning','tech.tls.p':'Autenticazione a chiave condivisa su ogni pacchetto. Heartbeat 3s con misurazione RTT. Riconnessione automatica multi-host con ritardo round-robin configurabile.',
    'tech.ppid.title':'PPID spoofing in RunPE','tech.ppid.p':'UpdateProcThreadAttribute imposta il processo genitore del processo iniettato su explorer.exe o winlogon.exe in base al livello di elevazione.',
    'tech.wd.title':'Watchdog impossibile da terminare','tech.wd.p':'4 processi guardiani in dllhost/SearchProtocolHost con PPID spoofing, sfalsati di 800ms. File lock + FileSystemWatcher per ripristino istantaneo.',
    'feat.mon.1':'Desktop remoto — DXGI + fallback GDI','feat.mon.2':'HVNC — desktop nascosto isolato','feat.mon.3':'Webcam — DirectShow + VFW','feat.mon.4':'Microfono — ascolto live + salvataggio WAV','feat.mon.5':'Keylogger — log su disco per data','feat.mon.6':'Monitor prestazioni — CPU / RAM / Rete','feat.mon.7':'Shell remota — cmd / PowerShell',
    'feat.adm.1':'Gestore file — sfoglia / carica / esegui','feat.adm.2':'Gestore processi — vista ad albero, icone','feat.adm.3':'Editor registro — HKLM + HKCU','feat.adm.4':'Gestore servizi / finestre / dispositivi','feat.adm.5':'Connessioni TCP + regole firewall','feat.adm.6':'Gestore avvio','feat.adm.7':'Programmi installati — disinstallazione silenziosa',
    'feat.off.1':'RunPE — in memoria + PPID spoof','feat.off.2':'Proxy SOCKS5 inverso','feat.off.3':'Crypto Clipper — 10 coin','feat.off.4':'Plugin DLL AutoTask — C++, compilati su richiesta','feat.off.5':'Miner XMR — target hollow configurabile','feat.off.6':'Notifica Telegram prima esecuzione','feat.off.7':'Deduplicazione AutoTask per HWID','hero.features':'40+ funzionalità','footer.built':'Creato da ','footer.lic':' — solo uso autorizzato.',
  },
  nl: {
    'nav.features':'Functies','nav.showcase':'Galerie','nav.pricing':'Prijzen',
    'hero.eyebrow':'open source · alleen geautoriseerd gebruik',
    'hero.h1a':'De RAT/C2 die ze','hero.h1b':'$2.000 voor vragen.','hero.h1c':'Gratis.',
    'hero.lead':'HVNC, DXGI-extern bureaublad op 60fps, webcam via DirectShow, process hollowing + PPID spoof, NativeAOT stub — 40+ functies. Alles wat de dure hebben. Zonder het prijskaartje.',
    'hero.cta1':'Bekijk op GitHub','hero.cta2':'Screenshots',
    's.features':'Wat het doet.',
    'col.mon':'Bewaking','col.adm':'Beheer','col.off':'Aanvallend',
    's.pricing':'De markt.','s.pricing.sub':'Wat anderen vragen voor hetzelfde — vaak slechter en gesloten broncode.',
    'price.closed':'commercieel, gesloten bron','price.leaked':'toch gereversed en gelekt','price.ours':'Broncode beschikbaar, volledige code op GitHub',
    's.showcase':'Echte screenshots.','s.showcase.sub':'Geen nep-demo\'s. Echte opnames van de server.',
    's.tech':'Geen snelkoppelingen.','s.tech.sub':'De details die een demo onderscheiden van iets dat je echt zou deployen.',
    's.hvnc':'HVNC in actie.','s.hvnc.sub':'Live demo — verborgen bureaublad, browsersessie, volledige controle. Geen montage.',
    's.contrib':'Bijdragers.','s.contrib.sub':'De mensen die dit gebouwd hebben.',
    'cta.h1':'Open source.','cta.h2':'Geen voorwaarden.',
    'cta.body':'Fork het. Bouw erop. Maak het van jou. Gebruik het alleen op systemen waarvoor je toestemming hebt.',
    'cta.legal':'Alleen voor geautoriseerd gebruik — red team, beveiligingsonderzoek, CTF.',
    'dd.hvnc.h3':'Verborgen Virtueel Netwerk Computergebruik',
    'dd.hvnc.p1':'HVNC maakt een volledig geïsoleerde Windows desktopsessie — onzichtbaar voor het doelwit. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram en Explorer starten rechtstreeks in de schaduwsessie. Het slachtoffer ziet niets. Jij ziet alles.',
    'dd.hvnc.p2a':'Elke browser ontvangt ','dd.hvnc.p2b':' en vult het HVNC-kader. Muis en toetsenbord doorgestuurd met pixelperfecte nauwkeurigheid. Klembord gesynchroniseerd op aanvraag.',
    'dd.hvnc.tag1':'geïsoleerde desktop','dd.hvnc.tag2':'11 apps','dd.hvnc.tag3':'klembord-sync','dd.hvnc.tag4':'realtime invoer',
    'dd.runpe.h3':'Process Hollowing — RunPE x64',
    'dd.runpe.p1a':'Er wordt geen nieuw bestand aangemaakt — de bestaande PE wordt via ','dd.runpe.p1b':' in het doelwit gemapt via ','dd.runpe.p1c':' — Windows lost relocaties en IAT automatisch op. De RIP van de thread wordt omgeleid naar het nieuwe ingangspunt en hervat.',
    'dd.runpe.p2a':'PPID-spoofing via ','dd.runpe.p2b':' laat het geïnjecteerde proces verschijnen als kind van explorer.exe of winlogon.exe. Taakbeheer, Process Explorer — niets verdachts.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'geen schijfschrijving','dd.runpe.tag3':'PPID-spoof','dd.runpe.tag4':'gesuspendeerd aangemaakt','dd.runpe.tag5':'geheugen-remap',
    'dd.gui.h3':'WPF-interface — DevExpress',
    'dd.gui.p1':'Gebouwd op WPF met DevExpress 25.2. Zijbalknavigatie in NanoCore-stijl — een iconenbalk links met gelabelde panelen per functiegroep. De volledige interface past zich in realtime aan het actieve thema aan.',
    'dd.gui.p2':'Een ingebouwde thema-kiezer biedt 20+ presets — Sero Dark (standaard), DevExpress Dark, Office 2019-familie, Visual Studio 2013-thema\'s, The Bezier en meer. Thema\'s worden direct toegepast zonder herstart. Interfacetaal instelbaar in 10 talen.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ thema\'s','dd.gui.tag3':'10 talen','dd.gui.tag4':'live thema-switch',
    'tech.tls.title':'TLS 1.2+ met certificaatpinning','tech.tls.p':'Gedeelde-sleutelauthenticatie op elk pakket. 3s heartbeat met RTT-meting. Automatische multi-host herverbinding met configureerbare round-robin vertraging.',
    'tech.ppid.title':'PPID-spoofing in RunPE','tech.ppid.p':'UpdateProcThreadAttribute stelt het bovenliggende proces van het geïnjecteerde proces in op explorer.exe of winlogon.exe afhankelijk van het verhogingsniveau.',
    'tech.wd.title':'Watchdog die niet gedood kan worden','tech.wd.p':'4 bewakersprocessen in dllhost/SearchProtocolHost met PPID-spoofing, gespreide 800ms. Bestandsvergrendeling + FileSystemWatcher voor onmiddellijk herstel.',
    'feat.mon.1':'Extern bureaublad — DXGI + GDI fallback','feat.mon.2':'HVNC — geïsoleerd verborgen bureaublad','feat.mon.3':'Webcam — DirectShow + VFW','feat.mon.4':'Microfoon — live luisteren + WAV opslaan','feat.mon.5':'Keylogger — schijflogboek per datum','feat.mon.6':'Prestatiemonitor — CPU / RAM / Net','feat.mon.7':'Externe shell — cmd / PowerShell',
    'feat.adm.1':'Bestandsbeheer — verkennen / uploaden / uitvoeren','feat.adm.2':'Procesbeheer — boomweergave, pictogrammen','feat.adm.3':'Register-editor — HKLM + HKCU','feat.adm.4':'Services / Vensters / Apparatenbeheer','feat.adm.5':'TCP-verbindingen + firewallregels','feat.adm.6':'Opstartbeheer','feat.adm.7':'Geïnstalleerde programma\'s — stille verwijdering',
    'feat.off.1':'RunPE — in geheugen + PPID-spoof','feat.off.2':'Reverse SOCKS5-proxy','feat.off.3':'Crypto Clipper — 10 munten','feat.off.4':'AutoTask DLL-plugins — C++, op aanvraag gecompileerd','feat.off.5':'XMR-miner — configureerbaar hollow-doel','feat.off.6':'Telegram eerste-uitvoer melding','feat.off.7':'AutoTask deduplicatie per HWID','hero.features':'40+ functies','footer.built':'Gemaakt door ','footer.lic':' — alleen bevoegd gebruik.',
  },
  tr: {
    'nav.features':'Özellikler','nav.showcase':'Galeri','nav.pricing':'Fiyatlar',
    'hero.eyebrow':'açık kaynak · yalnızca yetkili kullanım',
    'hero.h1a':'Onların $2.000\'e sattığı','hero.h1b':'RAT/C2.','hero.h1c':'Ücretsiz.',
    'hero.lead':'HVNC, 60fps DXGI uzak masaüstü, DirectShow ile webcam, process hollowing + PPID spoof, NativeAOT stub — 40+ özellik. Pahalıların sahip olduğu her şey. Fiyat etiketi olmadan.',
    'hero.cta1':'GitHub\'da Gör','hero.cta2':'Ekran Görüntüleri',
    's.features':'Ne yapar.',
    'col.mon':'İzleme','col.adm':'Yönetim','col.off':'Saldırı',
    's.pricing':'Pazar.','s.pricing.sub':'Diğerlerinin aynı şey için talep ettiği fiyat — genellikle daha kötü ve kapalı kaynak.',
    'price.closed':'ticari, kapalı kaynak','price.leaked':'zaten tersine mühendislik yapıldı ve sızdırıldı','price.ours':'Kaynak mevcut, tam kod GitHub\'da',
    's.showcase':'Gerçek ekran görüntüleri.','s.showcase.sub':'Sahte demolar yok. Sunucudan gerçek görüntüler.',
    's.tech':'Kısayol yok.','s.tech.sub':'Demoyu gerçekten dağıtacağınız bir şeyden ayıran ayrıntılar.',
    's.hvnc':'HVNC eylemde.','s.hvnc.sub':'Canlı demo — gizli masaüstü, tarayıcı oturumu, tam kontrol. Düzenleme yok.',
    's.contrib':'Katkıda Bulunanlar.','s.contrib.sub':'Bunu inşa eden insanlar.',
    'cta.h1':'Açık kaynak.','cta.h2':'Koşulsuz.',
    'cta.body':'Forklayın. Üzerine inşa edin. Kendinize ait yapın. Yalnızca yetkili olduğunuz sistemlerde kullanın.',
    'cta.legal':'Yalnızca yetkili kullanım için — red team, güvenlik araştırması, CTF.',
    'dd.hvnc.h3':'Gizli Sanal Ağ Bilişimi',
    'dd.hvnc.p1':'HVNC tamamen izole bir Windows masaüstü oturumu oluşturur — hedef için görünmez. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram ve Explorer doğrudan gölge oturumuna başlatılır. Kurban hiçbir şey görmez. Sen her şeyi görürsün.',
    'dd.hvnc.p2a':'Her tarayıcı ','dd.hvnc.p2b':' ile başlatılır ve HVNC çerçevesini doldurur. Fare ve klavye piksel hassasiyetiyle iletilir. Pano isteğe bağlı senkronize edilir.',
    'dd.hvnc.tag1':'izole masaüstü','dd.hvnc.tag2':'11 uygulama','dd.hvnc.tag3':'pano senkronu','dd.hvnc.tag4':'gerçek zamanlı giriş',
    'dd.runpe.h3':'Süreç Oyuklama — RunPE x64',
    'dd.runpe.p1a':'Yeni dosya oluşturulmaz — mevcut PE, ','dd.runpe.p1b':' aracılığıyla hedefe doğrudan eşlenir — ','dd.runpe.p1c':' — Windows yeniden konumlandırmaları ve IAT\'ı otomatik çözer. Thread RIP yeni giriş noktasına yönlendirilir ve devam eder.',
    'dd.runpe.p2a':'PPID sahteciliği (','dd.runpe.p2b':') enjekte edilen süreci explorer.exe veya winlogon.exe\'nin çocuğu olarak gösterir. Görev Yöneticisi, Process Explorer — şüpheli bir şey yok.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'diske yazma yok','dd.runpe.tag3':'PPID sahteciliği','dd.runpe.tag4':'askıya alınmış oluşturma','dd.runpe.tag5':'bellek remap',
    'dd.gui.h3':'WPF Arayüzü — DevExpress',
    'dd.gui.p1':'WPF ve DevExpress 25.2 ile oluşturulmuştur. NanoCore tarzı kenar çubuğu gezintisi — sol tarafta her özellik grubu için etiketli paneller içeren bir simge rayı. Arayüzün tamamı aktif temaya gerçek zamanlı olarak uyum sağlar.',
    'dd.gui.p2':'Yerleşik tema seçici 20\'den fazla ön ayar sunar — Sero Dark (varsayılan), DevExpress Dark, Office 2019 ailesi, Visual Studio 2013 temaları, The Bezier ve daha fazlası. Temalar yeniden başlatma gerektirmeden anında uygulanır. Arayüz dili 10 dil arasında değiştirilebilir.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ tema','dd.gui.tag3':'10 dil','dd.gui.tag4':'canlı tema geçişi',
    'tech.tls.title':'TLS 1.2+ sertifika sabitleme ile','tech.tls.p':'Her pakette paylaşımlı anahtar kimlik doğrulaması. RTT ölçümüyle 3s kalp atışı. Yapılandırılabilir round-robin gecikmeli çok ana bilgisayar otomatik yeniden bağlantı.',
    'tech.ppid.title':'RunPE\'de PPID sahteciliği','tech.ppid.p':'UpdateProcThreadAttribute, yükseltme düzeyine bağlı olarak enjekte edilen işlemin ebeveynini explorer.exe veya winlogon.exe olarak ayarlar.',
    'tech.wd.title':'Öldürülemeyen Watchdog','tech.wd.p':'PPID sahteciliğiyle dllhost/SearchProtocolHost\'ta 800ms aralıklı 4 koruyucu süreç. Anlık geri yükleme için dosya kilidi + FileSystemWatcher.',
    'feat.mon.1':'Uzak Masaüstü — DXGI + GDI geri dönüş','feat.mon.2':'HVNC — izole gizli masaüstü','feat.mon.3':'Webcam — DirectShow + VFW','feat.mon.4':'Mikrofon — canlı dinleme + WAV kaydetme','feat.mon.5':'Keylogger — tarihe göre disk günlüğü','feat.mon.6':'Performans Monitörü — CPU / RAM / Ağ','feat.mon.7':'Uzak Shell — cmd / PowerShell',
    'feat.adm.1':'Dosya Yöneticisi — göz at / yükle / çalıştır','feat.adm.2':'Süreç Yöneticisi — ağaç görünümü, simgeler','feat.adm.3':'Kayıt Defteri Düzenleyicisi — HKLM + HKCU','feat.adm.4':'Servis / Pencere / Aygıt Yöneticisi','feat.adm.5':'TCP Bağlantıları + güvenlik duvarı kuralları','feat.adm.6':'Başlangıç Yöneticisi','feat.adm.7':'Kurulu Programlar — sessiz kaldırma',
    'feat.off.1':'RunPE — bellekte + PPID spoof','feat.off.2':'Ters SOCKS5 proxy','feat.off.3':'Kripto Clipper — 10 coin','feat.off.4':'AutoTask DLL eklentileri — C++, isteğe bağlı derleme','feat.off.5':'XMR Madenci — yapılandırılabilir hollow hedef','feat.off.6':'İlk çalıştırma Telegram bildirimi','feat.off.7':'HWID\'ye göre AutoTask tekilleştirme','hero.features':'40+ özellik','footer.built':'Yapan: ','footer.lic':' — yalnızca yetkili kullanım.',
  },
  ko: {
    'nav.features':'기능','nav.showcase':'갤러리','nav.pricing':'가격',
    'hero.eyebrow':'오픈 소스 · 승인된 사용만 허용',
    'hero.h1a':'다른 곳에서 $2,000에 파는','hero.h1b':'RAT/C2.','hero.h1c':'무료.',
    'hero.lead':'HVNC, 60fps DXGI 원격 데스크톱, DirectShow 웹캠, 프로세스 할로윙 + PPID 스푸핑, NativeAOT 스텁 — 40개 이상의 기능. 비싼 도구들이 가진 모든 것. 가격표 없이.',
    'hero.cta1':'GitHub에서 보기','hero.cta2':'스크린샷',
    's.features':'기능 목록.',
    'col.mon':'모니터링','col.adm':'관리','col.off':'공격',
    's.pricing':'시장.','s.pricing.sub':'다른 곳이 같은 것에 청구하는 금액 — 대부분 더 나쁘고 소스 비공개.',
    'price.closed':'상업용, 비공개 소스','price.leaked':'어차피 리버싱되어 유출됨','price.ours':'소스 공개, GitHub에 전체 코드',
    's.showcase':'실제 스크린샷.','s.showcase.sub':'만들어진 데모 없음. 서버에서 실제 캡처.',
    's.tech':'지름길 없음.','s.tech.sub':'데모와 실제 배포 가능한 것을 구분하는 세부 사항.',
    's.hvnc':'HVNC 실전.','s.hvnc.sub':'라이브 데모 — 숨겨진 데스크톱, 브라우저 세션, 완전한 제어. 편집 없음.',
    's.contrib':'기여자.','s.contrib.sub':'이것을 만든 사람들.',
    'cta.h1':'오픈 소스.','cta.h2':'조건 없음.',
    'cta.body':'포크하세요. 위에 구축하세요. 당신의 것으로 만드세요. 권한이 있는 시스템에서만 사용하세요.',
    'cta.legal':'승인된 사용만 허용 — 레드팀 작전, 보안 연구, CTF.',
    'dd.hvnc.h3':'숨겨진 가상 네트워크 컴퓨팅',
    'dd.hvnc.p1':'HVNC는 완전히 격리된 Windows 데스크톱 세션을 생성합니다 — 대상에게 보이지 않습니다. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram, Explorer가 그림자 세션에 직접 실행됩니다. 피해자는 아무것도 보지 못합니다. 당신은 모든 것을 봅니다.',
    'dd.hvnc.p2a':'각 브라우저는 ','dd.hvnc.p2b':'로 실행되어 HVNC 프레임을 채웁니다. 마우스와 키보드는 픽셀 단위 정확도로 전달됩니다. 클립보드는 요청 시 동기화됩니다.',
    'dd.hvnc.tag1':'격리 데스크톱','dd.hvnc.tag2':'11개 앱','dd.hvnc.tag3':'클립보드 동기화','dd.hvnc.tag4':'실시간 입력',
    'dd.runpe.h3':'프로세스 할로윙 — RunPE x64',
    'dd.runpe.p1a':'새 파일이 생성되지 않습니다 — 기존 PE가 ','dd.runpe.p1b':'를 통해 대상에 직접 매핑됩니다 — ','dd.runpe.p1c':' — Windows가 재배치와 IAT를 자동으로 해결합니다. 스레드의 RIP가 새 진입점으로 리디렉션되고 재개됩니다.',
    'dd.runpe.p2a':'PPID 스푸핑 (','dd.runpe.p2b':')으로 주입된 프로세스가 explorer.exe 또는 winlogon.exe의 자식으로 표시됩니다. 작업 관리자, Process Explorer — 의심스러운 것이 없습니다.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'디스크 미기록','dd.runpe.tag3':'PPID 스푸핑','dd.runpe.tag4':'일시 중단 생성','dd.runpe.tag5':'메모리 리맵',
    'dd.gui.h3':'WPF 인터페이스 — DevExpress',
    'dd.gui.p1':'WPF와 DevExpress 25.2로 구축되었습니다. NanoCore 스타일의 사이드바 탐색 — 각 기능 그룹별 레이블 패널이 있는 왼쪽 아이콘 레일. 전체 UI가 활성 테마에 실시간으로 적응합니다.',
    'dd.gui.p2':'내장 테마 선택기는 20개 이상의 프리셋을 제공합니다 — Sero Dark(기본값), DevExpress Dark, Office 2019 계열, Visual Studio 2013 테마, The Bezier 등. 테마는 재시작 없이 즉시 적용됩니다. 인터페이스 언어는 10개 언어 중 선택 가능합니다.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ 테마','dd.gui.tag3':'10개 언어','dd.gui.tag4':'실시간 테마 전환',
    'tech.tls.title':'인증서 고정이 포함된 TLS 1.2+','tech.tls.p':'모든 패킷에 공유 키 인증. RTT 측정이 포함된 3초 하트비트. 구성 가능한 라운드 로빈 지연이 있는 다중 호스트 자동 재연결.',
    'tech.ppid.title':'RunPE에서 PPID 스푸핑','tech.ppid.p':'UpdateProcThreadAttribute는 권한 수준에 따라 주입된 프로세스의 부모를 explorer.exe 또는 winlogon.exe로 설정합니다.',
    'tech.wd.title':'종료할 수 없는 Watchdog','tech.wd.p':'PPID 스푸핑을 사용하여 dllhost/SearchProtocolHost에 800ms 간격으로 4개의 가디언 프로세스. 즉각적인 복원을 위한 파일 잠금 + FileSystemWatcher.',
    'feat.mon.1':'원격 데스크톱 — DXGI + GDI 폴백','feat.mon.2':'HVNC — 격리된 숨겨진 데스크톱','feat.mon.3':'웹캠 — DirectShow + VFW','feat.mon.4':'마이크 — 실시간 청취 + WAV 저장','feat.mon.5':'키로거 — 날짜별 디스크 로그','feat.mon.6':'성능 모니터 — CPU / RAM / 네트워크','feat.mon.7':'원격 Shell — cmd / PowerShell',
    'feat.adm.1':'파일 관리자 — 탐색 / 업로드 / 실행','feat.adm.2':'프로세스 관리자 — 트리 보기, 아이콘','feat.adm.3':'레지스트리 편집기 — HKLM + HKCU','feat.adm.4':'서비스 / 창 / 장치 관리자','feat.adm.5':'TCP 연결 + 방화벽 규칙','feat.adm.6':'시작 관리자','feat.adm.7':'설치된 프로그램 — 자동 제거',
    'feat.off.1':'RunPE — 메모리 내 + PPID 스푸핑','feat.off.2':'리버스 SOCKS5 프록시','feat.off.3':'암호화폐 클리퍼 — 10가지 코인','feat.off.4':'AutoTask DLL 플러그인 — C++, 주문형 컴파일','feat.off.5':'XMR 마이너 — 구성 가능한 hollow 대상','feat.off.6':'Telegram 최초 실행 알림','feat.off.7':'HWID별 AutoTask 중복 제거','hero.features':'40+ 기능','footer.built':'제작: ','footer.lic':' — 승인된 사용만.',
  },
  pl: {
    'nav.features':'Funkcje','nav.showcase':'Galeria','nav.pricing':'Ceny',
    'hero.eyebrow':'open source · tylko autoryzowane użycie',
    'hero.h1a':'RAT/C2, za który biorą','hero.h1b':'$2 000 gdzie indziej.','hero.h1c':'Za darmo.',
    'hero.lead':'HVNC, zdalny pulpit DXGI w 60fps, kamera przez DirectShow, process hollowing + PPID spoof, stub NativeAOT — ponad 40 funkcji. Wszystko, co mają drogie narzędzia. Bez ceny.',
    'hero.cta1':'Zobacz na GitHub','hero.cta2':'Zrzuty ekranu',
    's.features':'Co potrafi.',
    'col.mon':'Monitorowanie','col.adm':'Administracja','col.off':'Ofensywne',
    's.pricing':'Rynek.','s.pricing.sub':'Ile inni biorą za to samo — często gorsze i zamknięty kod.',
    'price.closed':'komercyjny, zamknięty kod','price.leaked':'odwrócony i wyciekł mimo to','price.ours':'Źródło dostępne, pełny kod na GitHub',
    's.showcase':'Prawdziwe zrzuty.','s.showcase.sub':'Bez inscenizowanych dem. Rzeczywiste zdjęcia z serwera.',
    's.tech':'Bez skrótów.','s.tech.sub':'Szczegóły, które oddzielają demo od czegoś, co naprawdę wdrożysz.',
    's.hvnc':'HVNC w akcji.','s.hvnc.sub':'Demo na żywo — ukryty pulpit, sesja przeglądarki, pełna kontrola. Bez montażu.',
    's.contrib':'Współtwórcy.','s.contrib.sub':'Ludzie, którzy to zbudowali.',
    'cta.h1':'Open source.','cta.h2':'Bez warunków.',
    'cta.body':'Forkuj. Buduj na tym. Zrób to swoim. Używaj tylko na systemach, do których masz autoryzację.',
    'cta.legal':'Tylko do autoryzowanego użytku — red team, badania bezpieczeństwa, CTF.',
    'dd.hvnc.h3':'Ukryta Wirtualna Sieć Komputerowa',
    'dd.hvnc.p1':'HVNC tworzy w pełni izolowaną sesję pulpitu Windows — niewidoczną dla celu. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram i Explorer uruchamiają się bezpośrednio w ukrytej sesji. Ofiara nic nie widzi. Ty widzisz wszystko.',
    'dd.hvnc.p2a':'Każda przeglądarka otrzymuje ','dd.hvnc.p2b':' i wypełnia ramkę HVNC. Mysz i klawiatura przekazywane z pikselową dokładnością. Schowek synchronizowany na żądanie.',
    'dd.hvnc.tag1':'izolowany pulpit','dd.hvnc.tag2':'11 aplikacji','dd.hvnc.tag3':'sync schowka','dd.hvnc.tag4':'wejście w czasie rzeczywistym',
    'dd.runpe.h3':'Process Hollowing — RunPE x64',
    'dd.runpe.p1a':'Żaden nowy plik nie jest tworzony — istniejący PE jest mapowany przez ','dd.runpe.p1b':' bezpośrednio do celu przez ','dd.runpe.p1c':' — Windows automatycznie rozwiązuje relokacje i IAT. RIP wątku jest przekierowywany do nowego punktu wejścia i wznawiany.',
    'dd.runpe.p2a':'PPID spoofing przez ','dd.runpe.p2b':' sprawia, że wstrzyknięty proces wygląda jak dziecko explorer.exe lub winlogon.exe. Menedżer zadań, Process Explorer — nic podejrzanego.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'bez zapisu na dysk','dd.runpe.tag3':'PPID spoof','dd.runpe.tag4':'zawieszone tworzenie','dd.runpe.tag5':'remap pamięci',
    'dd.gui.h3':'Interfejs WPF — DevExpress',
    'dd.gui.p1':'Zbudowany na WPF z DevExpress 25.2. Nawigacja boczna w stylu NanoCore — listwa ikon po lewej stronie z oznaczonymi panelami dla każdej grupy funkcji. Cały interfejs dostosowuje się do aktywnego motywu w czasie rzeczywistym.',
    'dd.gui.p2':'Wbudowany selektor motywów oferuje ponad 20 presetów — Sero Dark (domyślny), DevExpress Dark, rodzina Office 2019, motywy Visual Studio 2013, The Bezier i inne. Motywy stosują się na żywo bez restartu. Język interfejsu można zmienić spośród 10 języków.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ motywów','dd.gui.tag3':'10 języków','dd.gui.tag4':'zmiana motywu na żywo',
    'tech.tls.title':'TLS 1.2+ z przypięciem certyfikatu','tech.tls.p':'Uwierzytelnianie kluczem współdzielonym w każdym pakiecie. Heartbeat 3s z pomiarem RTT. Automatyczne ponowne połączenie z wieloma hostami z konfigurowalnym opóźnieniem round-robin.',
    'tech.ppid.title':'PPID spoofing w RunPE','tech.ppid.p':'UpdateProcThreadAttribute ustawia proces nadrzędny wstrzykniętego procesu na explorer.exe lub winlogon.exe w zależności od poziomu uprawnień.',
    'tech.wd.title':'Watchdog, którego nie można zabić','tech.wd.p':'4 procesy strażnicze w dllhost/SearchProtocolHost z PPID spoofingiem, rozłożone co 800ms. Blokada pliku + FileSystemWatcher dla natychmiastowego przywrócenia.',
    'feat.mon.1':'Zdalny pulpit — DXGI + GDI fallback','feat.mon.2':'HVNC — izolowany ukryty pulpit','feat.mon.3':'Kamera — DirectShow + VFW','feat.mon.4':'Mikrofon — nasłuch na żywo + zapis WAV','feat.mon.5':'Keylogger — dziennik dyskowy według daty','feat.mon.6':'Monitor wydajności — CPU / RAM / Sieć','feat.mon.7':'Zdalna powłoka — cmd / PowerShell',
    'feat.adm.1':'Menedżer plików — przeglądaj / wysyłaj / wykonuj','feat.adm.2':'Menedżer procesów — widok drzewa, ikony','feat.adm.3':'Edytor rejestru — HKLM + HKCU','feat.adm.4':'Menedżer usług / okien / urządzeń','feat.adm.5':'Połączenia TCP + reguły zapory','feat.adm.6':'Menedżer startowy','feat.adm.7':'Zainstalowane programy — ciche odinstalowanie',
    'feat.off.1':'RunPE — w pamięci + PPID spoof','feat.off.2':'Odwrotny proxy SOCKS5','feat.off.3':'Crypto Clipper — 10 monet','feat.off.4':'Wtyczki DLL AutoTask — C++, kompilowane na żądanie','feat.off.5':'Górnik XMR — konfigurowalne cele hollow','feat.off.6':'Powiadomienie Telegram przy pierwszym uruchomieniu','feat.off.7':'Deduplikacja AutoTask wg HWID','hero.features':'40+ funkcji','footer.built':'Autor: ','footer.lic':' — tylko autoryzowane użycie.',
  },
  id: {
    'nav.features':'Fitur','nav.showcase':'Galeri','nav.pricing':'Harga',
    'hero.eyebrow':'open source · hanya penggunaan terotorisasi',
    'hero.h1a':'RAT/C2 yang mereka jual','hero.h1b':'$2.000 di tempat lain.','hero.h1c':'Gratis.',
    'hero.lead':'HVNC, remote desktop DXGI 60fps, webcam via DirectShow, process hollowing + PPID spoof, stub NativeAOT — 40+ fitur. Semua yang dimiliki alat berbayar. Tanpa harga.',
    'hero.cta1':'Lihat di GitHub','hero.cta2':'Tangkapan Layar',
    's.features':'Yang bisa dilakukan.',
    'col.mon':'Pemantauan','col.adm':'Administrasi','col.off':'Ofensif',
    's.pricing':'Pasar.','s.pricing.sub':'Yang dikenakan orang lain untuk hal yang sama — sering lebih buruk, dan kode tertutup.',
    'price.closed':'komersial, kode tertutup','price.leaked':'di-reverse dan bocor bagaimanapun','price.ours':'Sumber tersedia, kode lengkap di GitHub',
    's.showcase':'Screenshot nyata.','s.showcase.sub':'Tidak ada demo palsu. Tangkapan nyata dari server.',
    's.tech':'Tidak ada jalan pintas.','s.tech.sub':'Detail yang memisahkan demo dari sesuatu yang benar-benar akan Anda deploy.',
    's.hvnc':'HVNC beraksi.','s.hvnc.sub':'Demo langsung — desktop tersembunyi, sesi browser, kendali penuh. Tanpa edit.',
    's.contrib':'Kontributor.','s.contrib.sub':'Orang-orang yang membangun ini.',
    'cta.h1':'Open source.','cta.h2':'Tanpa syarat.',
    'cta.body':'Fork. Bangun di atasnya. Jadikan milikmu. Gunakan hanya pada sistem yang Anda berwenang.',
    'cta.legal':'Hanya untuk penggunaan terotorisasi — red team, riset keamanan, CTF.',
    'dd.hvnc.h3':'Komputasi Jaringan Virtual Tersembunyi',
    'dd.hvnc.p1':'HVNC membuat sesi desktop Windows yang sepenuhnya terisolasi — tidak terlihat oleh target. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram dan Explorer diluncurkan langsung ke dalam sesi bayangan. Korban tidak melihat apa-apa. Anda melihat segalanya.',
    'dd.hvnc.p2a':'Setiap browser mendapatkan ','dd.hvnc.p2b':' dan mengisi bingkai HVNC. Mouse dan keyboard diteruskan dengan akurasi pixel-perfect. Clipboard disinkronkan sesuai permintaan.',
    'dd.hvnc.tag1':'desktop terisolasi','dd.hvnc.tag2':'11 aplikasi','dd.hvnc.tag3':'sinkron clipboard','dd.hvnc.tag4':'input real-time',
    'dd.runpe.h3':'Process Hollowing — RunPE x64',
    'dd.runpe.p1a':'Tidak ada file baru yang dibuat — PE yang ada dipetakan melalui ','dd.runpe.p1b':' langsung ke target melalui ','dd.runpe.p1c':' — Windows menyelesaikan relokasi dan IAT secara otomatis. RIP thread dialihkan ke titik masuk baru, lalu dilanjutkan.',
    'dd.runpe.p2a':'PPID spoofing melalui ','dd.runpe.p2b':' membuat proses yang disuntikkan tampak sebagai anak dari explorer.exe atau winlogon.exe. Task Manager, Process Explorer — tidak ada yang mencurigakan.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'tidak ada penulisan disk','dd.runpe.tag3':'PPID spoof','dd.runpe.tag4':'dibuat suspended','dd.runpe.tag5':'remap memori',
    'dd.gui.h3':'Antarmuka WPF — DevExpress',
    'dd.gui.p1':'Dibangun di atas WPF dengan DevExpress 25.2. Navigasi bilah samping gaya NanoCore — bilah ikon di sebelah kiri dengan panel berlabel untuk setiap grup fitur. Seluruh antarmuka menyesuaikan diri dengan tema aktif secara real time.',
    'dd.gui.p2':'Pemilih tema bawaan menawarkan 20+ preset — Sero Dark (default), DevExpress Dark, keluarga Office 2019, tema Visual Studio 2013, The Bezier, dan lainnya. Tema diterapkan langsung tanpa perlu restart. Bahasa antarmuka dapat diganti di antara 10 bahasa.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ tema','dd.gui.tag3':'10 bahasa','dd.gui.tag4':'ganti tema langsung',
    'tech.tls.title':'TLS 1.2+ dengan certificate pinning','tech.tls.p':'Autentikasi kunci bersama di setiap paket. Heartbeat 3 detik dengan pengukuran RTT. Koneksi ulang otomatis multi-host dengan penundaan round-robin yang dapat dikonfigurasi.',
    'tech.ppid.title':'PPID spoofing dalam RunPE','tech.ppid.p':'UpdateProcThreadAttribute menetapkan proses induk dari proses yang disuntikkan ke explorer.exe atau winlogon.exe tergantung pada tingkat elevasi.',
    'tech.wd.title':'Watchdog yang tidak bisa dimatikan','tech.wd.p':'4 proses penjaga di dllhost/SearchProtocolHost dengan PPID spoofing, selang 800ms. File lock + FileSystemWatcher untuk pemulihan instan.',
    'feat.mon.1':'Desktop Jarak Jauh — DXGI + GDI fallback','feat.mon.2':'HVNC — desktop tersembunyi terisolasi','feat.mon.3':'Webcam — DirectShow + VFW','feat.mon.4':'Mikrofon — dengarkan langsung + simpan WAV','feat.mon.5':'Keylogger — log disk berdasarkan tanggal','feat.mon.6':'Monitor Performa — CPU / RAM / Jaringan','feat.mon.7':'Shell Jarak Jauh — cmd / PowerShell',
    'feat.adm.1':'Manajer File — telusuri / unggah / jalankan','feat.adm.2':'Manajer Proses — tampilan pohon, ikon','feat.adm.3':'Editor Registri — HKLM + HKCU','feat.adm.4':'Manajer Layanan / Jendela / Perangkat','feat.adm.5':'Koneksi TCP + aturan firewall','feat.adm.6':'Manajer Startup','feat.adm.7':'Program Terinstal — uninstall diam-diam',
    'feat.off.1':'RunPE — dalam memori + PPID spoof','feat.off.2':'Proxy SOCKS5 terbalik','feat.off.3':'Crypto Clipper — 10 koin','feat.off.4':'Plugin DLL AutoTask — C++, dikompilasi sesuai permintaan','feat.off.5':'Penambang XMR — target hollow dapat dikonfigurasi','feat.off.6':'Notifikasi Telegram eksekusi pertama','feat.off.7':'Deduplikasi AutoTask per HWID','hero.features':'40+ fitur','footer.built':'Dibuat oleh ','footer.lic':' — hanya penggunaan resmi.',
  },
  vi: {
    'nav.features':'Tính năng','nav.showcase':'Thư viện','nav.pricing':'Giá cả',
    'hero.eyebrow':'mã nguồn mở · chỉ dùng khi có phép',
    'hero.h1a':'RAT/C2 mà họ bán','hero.h1b':'$2.000.','hero.h1c':'Miễn phí.',
    'hero.lead':'HVNC, màn hình từ xa DXGI 60fps, webcam qua DirectShow, process hollowing + PPID spoof, stub NativeAOT — hơn 40 tính năng. Tất cả những gì công cụ trả phí có. Không có giá.',
    'hero.cta1':'Xem trên GitHub','hero.cta2':'Ảnh chụp màn hình',
    's.features':'Tính năng.',
    'col.mon':'Giám sát','col.adm':'Quản trị','col.off':'Tấn công',
    's.pricing':'Thị trường.','s.pricing.sub':'Những gì người khác tính phí cho cùng thứ — thường tệ hơn và mã nguồn đóng.',
    'price.closed':'thương mại, mã nguồn đóng','price.leaked':'đã bị reverse và rò rỉ dù sao','price.ours':'Mã nguồn có sẵn, toàn bộ code trên GitHub',
    's.showcase':'Ảnh chụp thực tế.','s.showcase.sub':'Không có demo dàn dựng. Ảnh chụp thực từ máy chủ.',
    's.tech':'Không có đường tắt.','s.tech.sub':'Chi tiết phân biệt demo với thứ bạn thực sự deploy.',
    's.hvnc':'HVNC trong thực chiến.','s.hvnc.sub':'Demo trực tiếp — màn hình ẩn, phiên trình duyệt, kiểm soát hoàn toàn. Không chỉnh sửa.',
    's.contrib':'Cộng tác viên.','s.contrib.sub':'Những người đã xây dựng điều này.',
    'cta.h1':'Mã nguồn mở.','cta.h2':'Không điều kiện.',
    'cta.body':'Fork nó. Xây dựng trên đó. Làm của bạn. Chỉ dùng trên hệ thống bạn có quyền.',
    'cta.legal':'Chỉ dùng khi được phép — red team, nghiên cứu bảo mật, CTF.',
    'dd.hvnc.h3':'Mạng Máy Tính Ảo Ẩn',
    'dd.hvnc.p1':'HVNC tạo ra một phiên máy tính để bàn Windows hoàn toàn cô lập — vô hình với mục tiêu. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram và Explorer khởi chạy trực tiếp vào phiên ẩn. Nạn nhân không thấy gì. Bạn thấy tất cả.',
    'dd.hvnc.p2a':'Mỗi trình duyệt nhận ','dd.hvnc.p2b':' và lấp đầy khung HVNC. Chuột và bàn phím được chuyển tiếp với độ chính xác pixel. Clipboard đồng bộ theo yêu cầu.',
    'dd.hvnc.tag1':'desktop cô lập','dd.hvnc.tag2':'11 ứng dụng','dd.hvnc.tag3':'đồng bộ clipboard','dd.hvnc.tag4':'nhập liệu thời gian thực',
    'dd.runpe.h3':'Process Hollowing — RunPE x64',
    'dd.runpe.p1a':'Không tạo file mới — PE hiện có được ánh xạ qua ','dd.runpe.p1b':' vào mục tiêu qua ','dd.runpe.p1c':' — Windows tự động giải quyết relocation và IAT. RIP của thread được chuyển hướng đến điểm vào mới, sau đó tiếp tục.',
    'dd.runpe.p2a':'PPID spoofing qua ','dd.runpe.p2b':' khiến tiến trình bị inject xuất hiện như con của explorer.exe hoặc winlogon.exe. Task Manager, Process Explorer — không có gì đáng ngờ.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'không ghi đĩa','dd.runpe.tag3':'PPID spoof','dd.runpe.tag4':'tạo trạng thái tạm dừng','dd.runpe.tag5':'remap bộ nhớ',
    'dd.gui.h3':'Giao diện WPF — DevExpress',
    'dd.gui.p1':'Được xây dựng trên WPF với DevExpress 25.2. Điều hướng thanh bên kiểu NanoCore — thanh biểu tượng bên trái với các bảng có nhãn cho từng nhóm tính năng. Toàn bộ giao diện thích nghi với chủ đề đang hoạt động theo thời gian thực.',
    'dd.gui.p2':'Bộ chọn chủ đề tích hợp cung cấp hơn 20 cài đặt sẵn — Sero Dark (mặc định), DevExpress Dark, bộ Office 2019, chủ đề Visual Studio 2013, The Bezier và nhiều hơn nữa. Chủ đề được áp dụng trực tiếp không cần khởi động lại. Ngôn ngữ giao diện có thể chuyển đổi giữa 10 ngôn ngữ.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ chủ đề','dd.gui.tag3':'10 ngôn ngữ','dd.gui.tag4':'chuyển chủ đề trực tiếp',
    'tech.tls.title':'TLS 1.2+ với ghim chứng chỉ','tech.tls.p':'Xác thực khóa chia sẻ trên mọi gói tin. Heartbeat 3 giây với đo RTT. Tự động kết nối lại nhiều host với độ trễ round-robin có thể cấu hình.',
    'tech.ppid.title':'PPID spoofing trong RunPE','tech.ppid.p':'UpdateProcThreadAttribute đặt tiến trình cha của tiến trình được inject thành explorer.exe hoặc winlogon.exe tùy theo cấp quyền.',
    'tech.wd.title':'Watchdog không thể bị diệt','tech.wd.p':'4 tiến trình bảo vệ trong dllhost/SearchProtocolHost với PPID spoofing, lệch nhau 800ms. File lock + FileSystemWatcher để khôi phục ngay lập tức.',
    'feat.mon.1':'Màn hình từ xa — DXGI + GDI dự phòng','feat.mon.2':'HVNC — màn hình ẩn cô lập','feat.mon.3':'Webcam — DirectShow + VFW','feat.mon.4':'Microphone — nghe trực tiếp + lưu WAV','feat.mon.5':'Keylogger — ghi nhật ký theo ngày','feat.mon.6':'Màn hình hiệu suất — CPU / RAM / Mạng','feat.mon.7':'Shell từ xa — cmd / PowerShell',
    'feat.adm.1':'Quản lý File — duyệt / tải lên / thực thi','feat.adm.2':'Quản lý tiến trình — dạng cây, biểu tượng','feat.adm.3':'Trình chỉnh sửa registry — HKLM + HKCU','feat.adm.4':'Quản lý dịch vụ / cửa sổ / thiết bị','feat.adm.5':'Kết nối TCP + quy tắc tường lửa','feat.adm.6':'Quản lý khởi động','feat.adm.7':'Chương trình đã cài — gỡ cài đặt im lặng',
    'feat.off.1':'RunPE — trong bộ nhớ + PPID spoof','feat.off.2':'Proxy SOCKS5 ngược','feat.off.3':'Crypto Clipper — 10 coin','feat.off.4':'Plugin DLL AutoTask — C++, biên dịch theo yêu cầu','feat.off.5':'Trình đào XMR — hollow target có thể cấu hình','feat.off.6':'Thông báo Telegram lần chạy đầu tiên','feat.off.7':'Loại trùng AutoTask theo HWID','hero.features':'40+ tính năng','footer.built':'Tác giả: ','footer.lic':' — chỉ sử dụng được phép.',
  },
  uk: {
    'nav.features':'Функції','nav.showcase':'Галерея','nav.pricing':'Ціни',
    'hero.eyebrow':'відкритий код · лише авторизоване використання',
    'hero.h1a':'RAT/C2, за який беруть','hero.h1b':'$2,000 деінде.','hero.h1c':'Безкоштовно.',
    'hero.lead':'HVNC, віддалений стіл DXGI 60fps, вебкамера через DirectShow, process hollowing + PPID spoof, стаб NativeAOT — 40+ функцій. Все, що є у платних. Без цінника.',
    'hero.cta1':'Переглянути на GitHub','hero.cta2':'Скріншоти',
    's.features':'Що вміє.',
    'col.mon':'Моніторинг','col.adm':'Адміністрування','col.off':'Атака',
    's.pricing':'Ринок.','s.pricing.sub':'Що інші беруть за те саме — часто гірше і з закритим кодом.',
    'price.closed':'комерційний, закритий код','price.leaked':'зрештою злито','price.ours':'Вихідний код доступний, повний код на GitHub',
    's.showcase':'Реальні скріншоти.','s.showcase.sub':'Без постановочних демо. Реальні знімки з сервера.',
    's.tech':'Без компромісів.','s.tech.sub':'Деталі, що відрізняють демо від реально розгорнутого інструменту.',
    's.hvnc':'HVNC у дії.','s.hvnc.sub':'Живе демо — прихований стіл, сесія браузера, повний контроль. Без монтажу.',
    's.contrib':'Учасники.','s.contrib.sub':'Люди, які це побудували.',
    'cta.h1':'Відкритий код.','cta.h2':'Без умов.',
    'cta.body':'Форкайте. Будуйте на цій основі. Зробіть своїм. Використовуйте лише на дозволених системах.',
    'cta.legal':'Лише для авторизованого використання — red team, дослідження безпеки, CTF.',
    'dd.hvnc.h3':'Прихована Віртуальна Мережа',
    'dd.hvnc.p1':'HVNC створює повністю ізольований сеанс робочого стола Windows — невидимий для цілі. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram та Explorer запускаються прямо у тіньовому сеансі. Жертва нічого не бачить. Ви бачите все.',
    'dd.hvnc.p2a':'Кожен браузер отримує ','dd.hvnc.p2b':' і заповнює кадр HVNC. Миша та клавіатура передаються з піксельною точністю. Буфер обміну синхронізується на вимогу.',
    'dd.hvnc.tag1':'ізольований стіл','dd.hvnc.tag2':'11 застосунків','dd.hvnc.tag3':'синхронізація буфера','dd.hvnc.tag4':'введення в реальному часі',
    'dd.runpe.h3':'Hollowing Процесу — RunPE x64',
    'dd.runpe.p1a':'Новий файл не створюється — наявний PE маппується через ','dd.runpe.p1b':' у цільовий процес через ','dd.runpe.p1c':' — Windows автоматично вирішує релокації та IAT. RIP потоку перенаправляється на нову точку входу і поновлюється.',
    'dd.runpe.p2a':'PPID-спуфінг через ','dd.runpe.p2b':' робить інжектований процес дочірнім до explorer.exe або winlogon.exe. Диспетчер завдань, Process Explorer — нічого підозрілого.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'без запису на диск','dd.runpe.tag3':'PPID-спуфінг','dd.runpe.tag4':'призупинене створення','dd.runpe.tag5':'ремап пам\'яті',
    'dd.gui.h3':'Інтерфейс WPF — DevExpress',
    'dd.gui.p1':'Побудований на WPF з DevExpress 25.2. Навігація через бічну панель у стилі NanoCore — рейка іконок ліворуч із підписаними панелями для кожної групи функцій. Весь інтерфейс адаптується до активної теми в реальному часі.',
    'dd.gui.p2':'Вбудований вибір тем пропонує понад 20 пресетів — Sero Dark (за замовчуванням), DevExpress Dark, сімейство Office 2019, теми Visual Studio 2013, The Bezier та інші. Теми застосовуються миттєво без перезапуску. Мова інтерфейсу перемикається між 10 мовами.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ тем','dd.gui.tag3':'10 мов','dd.gui.tag4':'перемикання теми наживо',
    'tech.tls.title':'TLS 1.2+ із закріпленням сертифіката','tech.tls.p':'Аутентифікація спільним ключем у кожному пакеті. Heartbeat 3s з вимірюванням RTT. Автоматичне перепідключення до декількох хостів з налаштовуваною затримкою round-robin.',
    'tech.ppid.title':'PPID-спуфінг у RunPE','tech.ppid.p':'UpdateProcThreadAttribute встановлює батьківський процес інжектованого процесу як explorer.exe або winlogon.exe залежно від рівня привілеїв.',
    'tech.wd.title':'Watchdog, який неможливо вбити','tech.wd.p':'4 процеси-охоронці в dllhost/SearchProtocolHost з PPID-спуфінгом, рознесені на 800ms. Блокування файлу + FileSystemWatcher для миттєвого відновлення.',
    'feat.mon.1':'Віддалений стіл — DXGI + GDI fallback','feat.mon.2':'HVNC — ізольований прихований стіл','feat.mon.3':'Вебкамера — DirectShow + VFW','feat.mon.4':'Мікрофон — прослуховування в реальному часі + збереження WAV','feat.mon.5':'Кейлоггер — журнал на диску за датою','feat.mon.6':'Монітор продуктивності — CPU / ОЗУ / Мережа','feat.mon.7':'Віддалена оболонка — cmd / PowerShell',
    'feat.adm.1':'Файловий менеджер — перегляд / завантаження / виконання','feat.adm.2':'Менеджер процесів — дерево, іконки','feat.adm.3':'Редактор реєстру — HKLM + HKCU','feat.adm.4':'Менеджер служб / вікон / пристроїв','feat.adm.5':'TCP-з\'єднання + правила брандмауера','feat.adm.6':'Менеджер автозапуску','feat.adm.7':'Встановлені програми — тихе видалення',
    'feat.off.1':'RunPE — в пам\'яті + PPID-спуф','feat.off.2':'Зворотний проксі SOCKS5','feat.off.3':'Crypto Clipper — 10 монет','feat.off.4':'Плагіни AutoTask DLL — C++, компілюються на вимогу','feat.off.5':'Майнер XMR — налаштовувана ціль','feat.off.6':'Telegram-сповіщення при першому запуску','feat.off.7':'Дедуплікація AutoTask за HWID','hero.features':'40+ функцій','footer.built':'Створено ','footer.lic':' — лише авторизоване використання.',
  },
  he: {
    'nav.features':'תכונות','nav.showcase':'תצוגה','nav.pricing':'תמחור',
    'hero.eyebrow':'קוד פתוח · שימוש מורשה בלבד',
    'hero.h1a':'ה-RAT/C2 שגובים עליו','hero.h1b':'$2,000 במקומות אחרים.','hero.h1c':'חינם.',
    'hero.lead':'HVNC, שולחן עבודה מרוחק DXGI ב-60fps, מצלמת רשת דרך DirectShow, process hollowing עם PPID spoof, NativeAOT stub — 40+ תכונות. כל מה שיש לכלים היקרים. בלי תגית המחיר.',
    'hero.cta1':'צפה ב-GitHub','hero.cta2':'צילומי מסך',
    's.features':'מה הוא עושה.',
    'col.mon':'ניטור','col.adm':'ניהול','col.off':'התקפי',
    's.pricing':'השוק.','s.pricing.sub':'מה אחרים גובים על אותו דבר — לרוב גרוע יותר, עם קוד סגור.',
    'price.closed':'מסחרי, קוד סגור','price.leaked':'הופך הנדסית ודלף ממילא','price.ours':'קוד מקור זמין, קוד מלא ב-GitHub',
    's.showcase':'צילומי מסך אמיתיים.','s.showcase.sub':'ללא הדגמות מבוימות. צילומים אמיתיים מהשרת.',
    's.tech':'ללא קיצורי דרך.','s.tech.sub':'הפרטים שמפרידים הדגמה ממשהו שתפרוס בפועל.',
    's.hvnc':'HVNC בפעולה.','s.hvnc.sub':'הדגמה חיה — שולחן עבודה נסתר, סשן דפדפן, שליטה מלאה. ללא עריכה.',
    's.contrib':'תורמים.','s.contrib.sub':'האנשים שבנו את זה.',
    'cta.h1':'קוד פתוח.','cta.h2':'ללא תנאים.',
    'cta.body':'Fork אותו. בנה עליו. עשה אותו שלך. השתמש בו רק על מערכות שיש לך הרשאה עליהן.',
    'cta.legal':'לשימוש מורשה בלבד — red team, מחקר אבטחה, CTF. אתה אחראי לשימוש שלך.',
    'dd.hvnc.h3':'מחשוב רשת וירטואלי נסתר',
    'dd.hvnc.p1':'HVNC יוצר סשן שולחן עבודה של Windows מבודד לחלוטין — בלתי נראה לקורבן. Chrome, Edge, Firefox, Brave, Vivaldi, Opera, Opera GX, Telegram, Discord, AyuGram ו-Explorer מופעלים ישירות לתוך הסשן הצללי. הקורבן לא רואה דבר. אתה רואה הכל.',
    'dd.hvnc.p2a':'כל דפדפן מקבל ','dd.hvnc.p2b':' וממלא את מסגרת HVNC. עכבר ומקלדת מועברים בדיוק פיקסלי. לוח הגזירות מסונכרן לפי דרישה.',
    'dd.hvnc.tag1':'שולחן עבודה מבודד','dd.hvnc.tag2':'11 אפליקציות','dd.hvnc.tag3':'סנכרון לוח גזירות','dd.hvnc.tag4':'קלט בזמן אמת',
    'dd.runpe.h3':'חלול תהליכים — RunPE x64',
    'dd.runpe.p1a':'לא נוצר קובץ חדש — ה-PE הקיים ממופה דרך ','dd.runpe.p1b':' אל תוך היעד דרך ','dd.runpe.p1c':' — Windows פותר relocations ו-IAT אוטומטית. ה-RIP של הת\'ריד מנותב מחדש לנקודת הכניסה החדשה ומחדש.',
    'dd.runpe.p2a':'זיוף PPID דרך ','dd.runpe.p2b':' גורם לתהליך המוזרק להיראות כבן של explorer.exe או winlogon.exe. מנהל המשימות, Process Explorer — אין שום דבר חשוד.',
    'dd.runpe.tag1':'x64','dd.runpe.tag2':'ללא כתיבה לדיסק','dd.runpe.tag3':'זיוף PPID','dd.runpe.tag4':'יצירה מושעית','dd.runpe.tag5':'רמאפינג זיכרון',
    'dd.gui.h3':'ממשק WPF — DevExpress',
    'dd.gui.p1':'בנוי על WPF עם DevExpress 25.2. ניווט בסרגל צד בסגנון NanoCore — פס אייקונים בצד שמאל עם לוחות מסומנים לכל קבוצת תכונות. כל הממשק מסתגל לנושא הפעיל בזמן אמת.',
    'dd.gui.p2':'בוחר ערכות נושא מובנה מציע יותר מ-20 הגדרות קבועות מראש — Sero Dark (ברירת מחדל), DevExpress Dark, משפחת Office 2019, ערכות Visual Studio 2013, The Bezier ועוד. ערכות הנושא מוחלות מיידית ללא הפעלה מחדש. שפת הממשק ניתנת להחלפה בין 10 שפות.',
    'dd.gui.tag1':'WPF · DevExpress 25.2','dd.gui.tag2':'20+ ערכות נושא','dd.gui.tag3':'10 שפות','dd.gui.tag4':'החלפת ערכת נושא חיה',
    'tech.tls.title':'TLS 1.2+ עם הצמדת אישור','tech.tls.p':'אימות מפתח משותף בכל חבילה. פעימת לב 3 שניות עם מדידת RTT. חיבור מחדש אוטומטי לריבוי מארחים עם עיכוב round-robin ניתן להגדרה.',
    'tech.ppid.title':'זיוף PPID ב-RunPE','tech.ppid.p':'UpdateProcThreadAttribute מגדיר את תהליך האב של התהליך המוזרק כ-explorer.exe או winlogon.exe בהתאם לרמת ההרשאות.',
    'tech.wd.title':'Watchdog שלא ניתן להרוג','tech.wd.p':'4 תהליכי שמירה ב-dllhost/SearchProtocolHost עם זיוף PPID, ברווחים של 800ms. נעילת קובץ + FileSystemWatcher לשחזור מיידי.',
    'feat.mon.1':'שולחן עבודה מרוחק — DXGI + GDI גיבוי','feat.mon.2':'HVNC — שולחן עבודה נסתר מבודד','feat.mon.3':'מצלמת רשת — DirectShow + VFW','feat.mon.4':'מיקרופון — האזנה חיה + שמירת WAV','feat.mon.5':'Keylogger — יומן דיסק לפי תאריך','feat.mon.6':'מוניטור ביצועים — CPU / RAM / רשת','feat.mon.7':'Shell מרוחק — cmd / PowerShell',
    'feat.adm.1':'מנהל קבצים — עיון / העלאה / הרצה','feat.adm.2':'מנהל תהליכים — תצוגת עץ, אייקונים','feat.adm.3':'עורך רג\'יסטרי — HKLM + HKCU','feat.adm.4':'מנהל שירותים / חלונות / התקנים','feat.adm.5':'חיבורי TCP + כללי חומת אש','feat.adm.6':'מנהל הפעלה','feat.adm.7':'תוכניות מותקנות — הסרה שקטה',
    'feat.off.1':'RunPE — בזיכרון + PPID spoof','feat.off.2':'פרוקסי SOCKS5 הפוך','feat.off.3':'Crypto Clipper — 10 מטבעות','feat.off.4':'פלאגינים DLL AutoTask — C++, מקומפל לפי דרישה','feat.off.5':'מכרה XMR — יעד hollow ניתן להגדרה','feat.off.6':'הודעת Telegram בהרצה ראשונה','feat.off.7':'ביטול כפילויות AutoTask לפי HWID','hero.features':'40+ תכונות','footer.built':'נבנה על ידי ','footer.lic':' — לשימוש מורשה בלבד.',
  },
};

/* Apply a language: swap textContent on all [data-i18n] elements */
function applyLang(code) {
  const t = LANGS[code] || LANGS.en;
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const k = el.dataset.i18n;
    if (t[k] !== undefined) el.textContent = t[k];
  });
  const html = document.documentElement;
  html.lang = code;
  html.dir  = (code === 'ar' || code === 'he') ? 'rtl' : 'ltr';
  localStorage.setItem('sero-lang', code);
  document.querySelectorAll('.lang-opt').forEach(b => b.classList.toggle('active', b.dataset.lang === code));
  const cur = document.getElementById('lang-current');
  if (cur) cur.textContent = code.toUpperCase();
}

/* Auto-detect on first load */
(function () {
  const saved   = localStorage.getItem('sero-lang');
  const browser = (navigator.language || 'en').slice(0, 2).toLowerCase();
  applyLang(LANGS[saved] ? saved : LANGS[browser] ? browser : 'en');
})();

/* ══════════════════════════════════════════════════════════════════
   Three.js — Stellar Field
   ══════════════════════════════════════════════════════════════════ */
(function () {
  const canvas = document.getElementById('bg-canvas');
  if (!canvas || typeof THREE === 'undefined') return;

  const W = window.innerWidth, H = window.innerHeight;
  if (W < 768) { canvas.style.display = 'none'; return; }
  const mobile = false;

  const renderer = new THREE.WebGLRenderer({ canvas, alpha: false, antialias: false });
  renderer.setPixelRatio(Math.min(devicePixelRatio, mobile ? 1.5 : 2));
  renderer.setClearColor(0x06080f, 1);

  const scene = new THREE.Scene();
  /* Depth-parallax groups — bg barely moves, fg moves most with camera */
  const bgGroup  = new THREE.Group();
  const midGroup = new THREE.Group();
  const fgGroup  = new THREE.Group();
  scene.add(bgGroup, midGroup, fgGroup);

  const camera = new THREE.PerspectiveCamera(75, W / H, 0.1, 1000);
  camera.position.z = 1;

  /* ── Parallax — mouse on desktop, touch drag on mobile ────────────── */
  let mx = 0, my = 0, crx = 0, cry = 0;
  if (!mobile) {
    window.addEventListener('mousemove', e => {
      mx = (e.clientX / window.innerWidth  - 0.5) * 0.28;
      my = (e.clientY / window.innerHeight - 0.5) * 0.18;
    }, { passive: true });
  } else {
    /* Mobile: strong tilt — finger position maps to camera angle */
    function applyTouch(touch) {
      mx = (touch.clientX / window.innerWidth  - 0.5) * 0.90;
      my = (touch.clientY / window.innerHeight - 0.5) * 0.60;
    }
    window.addEventListener('touchstart', e => applyTouch(e.touches[0]), { passive: true });
    window.addEventListener('touchmove',  e => applyTouch(e.touches[0]), { passive: true });
    window.addEventListener('touchend',   () => { mx = 0; my = 0; }, { passive: true });
  }

  /* ── Stellar spectral colors — real star palette ──────────────────── */
  // Hot stars dominate visibility. Bias toward blue-white for site palette cohesion.
  const SC = [
    [1.00, 1.00, 1.00], // A-type: pure white   (Sirius, Vega)
    [0.88, 0.93, 1.00], // B-type: blue-white    (Rigel, Spica)
    [0.80, 0.88, 1.00], // B-type: cooler blue
    [0.72, 0.82, 1.00], // O-type: deep blue     (most luminous)
    [1.00, 0.97, 0.90], // F-type: warm white    (Procyon)
    [0.95, 0.95, 1.00], // A-type: near-white variant
    [0.90, 0.82, 1.00], // Lavender              (on-brand accent)
    [1.00, 0.96, 0.68], // G-type: yellow-white  (Sun, Capella)
    [1.00, 0.82, 0.46], // K-type: orange        (Arcturus, Aldebaran)
    [1.00, 0.60, 0.30], // M-type: red-orange    (Betelgeuse, Antares)
  ];

  /* ── Nebula wisps — distant colour washes ────────────────────────── */
  function nebula(sz, r1,g1,b1, a1, r2,g2,b2, a2, worldSz, px,py,pz, grp = bgGroup) {
    const cv = document.createElement('canvas'); cv.width = cv.height = sz;
    const ctx = cv.getContext('2d'), c = sz / 2;
    const gr = ctx.createRadialGradient(c, c, 0, c, c, c);
    gr.addColorStop(0,    `rgba(${r1},${g1},${b1},${a1})`);
    gr.addColorStop(0.42, `rgba(${r2},${g2},${b2},${a2})`);
    gr.addColorStop(1,    'rgba(0,0,0,0)');
    ctx.fillStyle = gr; ctx.fillRect(0, 0, sz, sz);
    const sp = new THREE.Sprite(new THREE.SpriteMaterial({
      map: new THREE.CanvasTexture(cv), transparent: true,
      depthWrite: false, blending: THREE.AdditiveBlending
    }));
    sp.scale.set(worldSz, worldSz, 1);
    sp.position.set(px, py, pz);
    grp.add(sp);
  }

  /* nebula wisps removed */

  /* ── Helper: random point on sphere ──────────────────────────────── */
  function sphPt(r) {
    const phi = Math.acos(2*Math.random()-1), th = Math.random()*Math.PI*2;
    return [r*Math.sin(phi)*Math.cos(th), r*Math.sin(phi)*Math.sin(th), r*Math.cos(phi)];
  }

  /* ── Soft-disk texture — makes point sprites appear as round glowing dots ── */
  function mkStarDot() {
    const sz = 64, cv = document.createElement('canvas');
    cv.width = cv.height = sz;
    const ctx = cv.getContext('2d'), c = sz / 2;
    const gr = ctx.createRadialGradient(c, c, 0, c, c, c);
    gr.addColorStop(0,    'rgba(255,255,255,1.0)');
    gr.addColorStop(0.18, 'rgba(255,255,255,0.95)');
    gr.addColorStop(0.42, 'rgba(255,255,255,0.52)');
    gr.addColorStop(0.70, 'rgba(255,255,255,0.10)');
    gr.addColorStop(1.0,  'rgba(255,255,255,0.00)');
    ctx.fillStyle = gr; ctx.fillRect(0, 0, sz, sz);
    return new THREE.CanvasTexture(cv);
  }
  const STAR_DOT = mkStarDot();

  /* ── Layer 1 — background field (many tiny dim dots, 1 px) ────────── */
  const BG_N = mobile ? 1100 : 3600;
  const bgP = new Float32Array(BG_N * 3);
  const bgC = new Float32Array(BG_N * 3);
  for (let i = 0; i < BG_N; i++) {
    const [x,y,z] = sphPt(370 + Math.random()*55);
    bgP[i*3]=x; bgP[i*3+1]=y; bgP[i*3+2]=z;
    const col = SC[Math.floor(Math.random()*SC.length)];
    const b = 0.16 + Math.random()*0.50;
    bgC[i*3]=col[0]*b; bgC[i*3+1]=col[1]*b; bgC[i*3+2]=col[2]*b;
  }
  const bgGeo = new THREE.BufferGeometry();
  bgGeo.setAttribute('position', new THREE.BufferAttribute(bgP, 3));
  bgGeo.setAttribute('color',    new THREE.BufferAttribute(bgC, 3));
  bgGroup.add(new THREE.Points(bgGeo, new THREE.PointsMaterial({
    size: 2.2, sizeAttenuation: false, vertexColors: true,
    map: STAR_DOT, alphaTest: 0.008,
    transparent: true, opacity: 0.90, depthWrite: false
  })));

  /* ── Milky Way band — tilted great-circle strip of extra-dim stars ── */
  if (!mobile) {
    const MW_N = 700;
    const mwP  = new Float32Array(MW_N * 3);
    const mwC  = new Float32Array(MW_N * 3);
    const tilt = Math.PI * 0.22; // ~40° tilt from equator
    const cosT = Math.cos(tilt), sinT = Math.sin(tilt);
    for (let i = 0; i < MW_N; i++) {
      const th  = Math.random() * Math.PI * 2;
      const phi = Math.PI/2 + (Math.random()-0.5) * 0.38; // ±11° band width
      const r   = 358 + Math.random() * 18;
      let x =  r * Math.sin(phi) * Math.cos(th);
      let y =  r * Math.sin(phi) * Math.sin(th);
      let z =  r * Math.cos(phi);
      const y2 = y * cosT - z * sinT;
      const z2 = y * sinT + z * cosT;
      mwP[i*3]=x; mwP[i*3+1]=y2; mwP[i*3+2]=z2;
      const col = SC[Math.floor(Math.random() * SC.length)];
      const b = 0.05 + Math.random() * 0.17;
      mwC[i*3]=col[0]*b; mwC[i*3+1]=col[1]*b; mwC[i*3+2]=col[2]*b;
    }
    const mwGeo = new THREE.BufferGeometry();
    mwGeo.setAttribute('position', new THREE.BufferAttribute(mwP, 3));
    mwGeo.setAttribute('color',    new THREE.BufferAttribute(mwC, 3));
    bgGroup.add(new THREE.Points(mwGeo, new THREE.PointsMaterial({
      size: 2.0, sizeAttenuation: false, vertexColors: true,
      map: STAR_DOT, alphaTest: 0.008,
      transparent: true, opacity: 0.68, depthWrite: false
    })));
  }

  /* ── Layer 2 — mid stars (2 px, per-star scintillation) ──────────── */
  const MID_N = mobile ? 220 : 650;
  const mP    = new Float32Array(MID_N * 3);
  const mC    = new Float32Array(MID_N * 3);
  const mBase = new Float32Array(MID_N * 3); // base rgb
  // Per-star twinkle: [phase1, freq1, phase2, freq2]
  const mTwk  = new Float32Array(MID_N * 4);
  for (let i = 0; i < MID_N; i++) {
    const [x,y,z] = sphPt(290 + Math.random()*60);
    mP[i*3]=x; mP[i*3+1]=y; mP[i*3+2]=z;
    const col = SC[Math.floor(Math.random()*SC.length)];
    const b = 0.55 + Math.random()*0.40;
    mBase[i*3]=col[0]*b; mBase[i*3+1]=col[1]*b; mBase[i*3+2]=col[2]*b;
    mC[i*3]=mBase[i*3]; mC[i*3+1]=mBase[i*3+1]; mC[i*3+2]=mBase[i*3+2];
    mTwk[i*4]   = Math.random()*Math.PI*2;
    mTwk[i*4+1] = 0.6 + Math.random()*2.0;
    mTwk[i*4+2] = Math.random()*Math.PI*2;
    mTwk[i*4+3] = 2.0 + Math.random()*4.5;
  }
  const mGeo = new THREE.BufferGeometry();
  mGeo.setAttribute('position', new THREE.BufferAttribute(mP, 3));
  const mColBuf = new THREE.BufferAttribute(mC, 3);
  mColBuf.setUsage(THREE.DynamicDrawUsage);
  mGeo.setAttribute('color', mColBuf);
  midGroup.add(new THREE.Points(mGeo, new THREE.PointsMaterial({
    size: 3.2, sizeAttenuation: false, vertexColors: true,
    map: STAR_DOT, alphaTest: 0.008,
    transparent: true, opacity: 1, depthWrite: false
  })));

  /* ── Layer 3 — bright stars (sprites, glow + diffraction spikes) ─── */
  const BRIGHT_N = mobile ? 12 : 26;
  const brightStars = [];

  function glowTex(r, g, b) {
    const sz = 128, cv = document.createElement('canvas');
    cv.width = cv.height = sz;
    const ctx = cv.getContext('2d'), c = sz/2;
    const gr = ctx.createRadialGradient(c,c,0,c,c,c);
    gr.addColorStop(0,    `rgba(${r},${g},${b},1)`);
    gr.addColorStop(0.05, `rgba(${r},${g},${b},0.96)`);
    gr.addColorStop(0.15, `rgba(${r},${g},${b},0.65)`);
    gr.addColorStop(0.35, `rgba(${Math.round(r*.7)},${Math.round(g*.75)},${b},0.18)`);
    gr.addColorStop(0.60, `rgba(${Math.round(r*.4)},${Math.round(g*.45)},${b},0.04)`);
    gr.addColorStop(1,    'rgba(0,0,0,0)');
    ctx.fillStyle = gr; ctx.fillRect(0,0,sz,sz);
    return new THREE.CanvasTexture(cv);
  }

  function spikeTex(r, g, b) {
    // 4-point diffraction spike (telescope star artifact)
    const sz = 256, cv = document.createElement('canvas');
    cv.width = cv.height = sz;
    const ctx = cv.getContext('2d'), c = sz/2;
    [[0,c,sz,c],[c,0,c,sz]].forEach(([x0,y0,x1,y1]) => {
      const gr = ctx.createLinearGradient(x0,y0,x1,y1);
      gr.addColorStop(0,    'rgba(0,0,0,0)');
      gr.addColorStop(0.30, `rgba(${r},${g},${b},0.10)`);
      gr.addColorStop(0.46, `rgba(${r},${g},${b},0.50)`);
      gr.addColorStop(0.50, `rgba(${r},${g},${b},0.85)`);
      gr.addColorStop(0.54, `rgba(${r},${g},${b},0.50)`);
      gr.addColorStop(0.70, `rgba(${r},${g},${b},0.10)`);
      gr.addColorStop(1,    'rgba(0,0,0,0)');
      ctx.fillStyle = gr;
      if (x0===0) ctx.fillRect(0,c-2,sz,4); else ctx.fillRect(c-2,0,4,sz);
    });
    return new THREE.CanvasTexture(cv);
  }

  for (let i = 0; i < BRIGHT_N; i++) {
    const [x,y,z] = sphPt(310 + Math.random()*50);
    const kind = Math.random();
    let rc,gc,bc;
    if (kind<0.28)       { rc=255;gc=255;bc=255; }   // white (A-type)
    else if (kind<0.50)  { rc=200;gc=222;bc=255; }   // blue-white (B-type)
    else if (kind<0.64)  { rc=155;gc=198;bc=255; }   // blue (O-type)
    else if (kind<0.76)  { rc=255;gc=245;bc=210; }   // warm white (F-type)
    else if (kind<0.86)  { rc=255;gc=218;bc=118; }   // yellow (G-type, Capella)
    else if (kind<0.94)  { rc=255;gc=172;bc=65;  }   // orange (K-type, Arcturus)
    else                 { rc=218;gc=182;bc=255; }   // lavender (on-brand)

    const base = mobile ? (1.4+Math.random()*4.2) : (1.8+Math.random()*7.5);
    const gSp  = new THREE.Sprite(new THREE.SpriteMaterial({
      map: glowTex(rc,gc,bc), transparent:true,
      depthWrite:false, blending:THREE.AdditiveBlending, opacity:0
    }));
    gSp.position.set(x,y,z); gSp.scale.set(base,base,1);
    fgGroup.add(gSp);

    // Diffraction spike only for the largest stars
    let spSp = null;
    if (base > (mobile ? 3.5 : 5.5)) {
      spSp = new THREE.Sprite(new THREE.SpriteMaterial({
        map: spikeTex(rc,gc,bc), transparent:true,
        depthWrite:false, blending:THREE.AdditiveBlending, opacity:0
      }));
      spSp.position.set(x,y,z); spSp.scale.set(base*3.0, base*3.0, 1);
      fgGroup.add(spSp);
    }

    brightStars.push({
      gSp, spSp, base,
      bOp: 0.62 + Math.random()*0.34,
      ph1: Math.random()*Math.PI*2, fr1: 1.1+Math.random()*2.8,
      ph2: Math.random()*Math.PI*2, fr2: 3.2+Math.random()*5.0,
      ph3: Math.random()*Math.PI*2, fr3: 7.5+Math.random()*8.5,
    });
  }

  /* ── Resize ──────────────────────────────────────────────────────── */
  let resizeTimer;
  function resize() {
    const w = window.innerWidth, h = window.innerHeight;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(resize, 120); }, { passive: true });
  resize();

  let paused = false;
  document.addEventListener('visibilitychange', () => {
    paused = document.hidden; if (!paused) { clock.start(); tick(); }
  });

  const clock = new THREE.Clock();
  let t = 0;

  function tick() {
    if (paused) return;
    requestAnimationFrame(tick);
    const dt = Math.min(clock.getDelta(), 0.05);
    t += dt;

    /* Sky drift — majestic Y sweep, no oscillation */
    scene.rotation.y += dt * 0.0032;

    /* Parallax — exponential easing (frame-rate independent) */
    const lf = 1 - Math.exp(-dt * (mobile ? 4.5 : 2.8));
    crx += (my - crx) * lf;
    cry += (mx - cry) * lf;
    camera.rotation.x = crx;
    camera.rotation.y = cry;

    /* Depth parallax — counter-rotate bg/mid so they appear farther away */
    bgGroup.rotation.x  = -crx * 0.80;  bgGroup.rotation.y  = -cry * 0.80;
    midGroup.rotation.x = -crx * 0.44;  midGroup.rotation.y = -cry * 0.44;

    /* Mid-star scintillation — two incommensurable sine waves */
    for (let i = 0; i < MID_N; i++) {
      const s1 = Math.sin(t * mTwk[i*4+1] + mTwk[i*4]);
      const s2 = Math.sin(t * mTwk[i*4+3] + mTwk[i*4+2]);
      const f  = 0.74 + 0.17*s1 + 0.09*s2; // range ≈ 0.48–1.00 (deeper flicker)
      mC[i*3]   = mBase[i*3]   * f;
      mC[i*3+1] = mBase[i*3+1] * f;
      mC[i*3+2] = mBase[i*3+2] * f;
    }
    mColBuf.needsUpdate = true;

    /* Bright star scintillation — three frequencies for aperiodic flicker */
    for (const st of brightStars) {
      const f1 = Math.sin(t * st.fr1 + st.ph1);
      const f2 = Math.sin(t * st.fr2 + st.ph2);
      const f3 = Math.sin(t * st.fr3 + st.ph3);
      const intensity = 0.70 + 0.16*f1 + 0.09*f2 + 0.05*f3;
      const op = st.bOp * Math.max(0.25, intensity);
      st.gSp.material.opacity = op;
      /* Atmospheric seeing: star "blooms" at peak brightness */
      const sc = st.base * (0.95 + 0.05*f1);
      st.gSp.scale.set(sc, sc, 1);
      if (st.spSp) {
        st.spSp.material.opacity = op * 0.52;
        st.spSp.scale.set(sc*3.0, sc*3.0, 1);
      }
    }

    renderer.render(scene, camera);
  }
  tick();

})();

/* ── Background music ── */
(function () {
  const audio = document.getElementById('bg-music');
  if (!audio) return;
  audio.volume = 0.28;
  function tryPlay() { audio.play().catch(() => {}); }
  tryPlay();
  ['click','keydown','touchstart'].forEach(ev =>
    document.addEventListener(ev, tryPlay, { once: true, passive: true }));
})();

/* ── Nav scroll ── */
window.addEventListener('scroll', () => {
  document.getElementById('nav').classList.toggle('scrolled', window.scrollY > 40);
}, { passive: true });

/* ── Scroll reveal ── */
const revealIO = new IntersectionObserver(entries => {
  entries.forEach(({ isIntersecting, target }) => {
    if (isIntersecting) { target.classList.add('visible'); revealIO.unobserve(target); }
  });
}, { threshold: 0, rootMargin: '0px 0px -40px 0px' });
document.querySelectorAll('.reveal').forEach((el, i) => {
  el.style.transitionDelay = (i % 3) * 45 + 'ms';
  revealIO.observe(el);
});

/* ── Lightbox ── */
(function () {
  const lb    = document.getElementById('lightbox');
  const lbImg = document.getElementById('lightbox-img');
  const lbBtn = document.getElementById('lightbox-close');
  if (!lb || !lbImg) return;
  function open(src, alt) {
    lbImg.src = src; lbImg.alt = alt || '';
    lb.classList.add('open'); document.body.style.overflow = 'hidden';
  }
  function close() {
    lb.classList.remove('open'); document.body.style.overflow = '';
    setTimeout(() => { lbImg.src = ''; }, 200);
  }
  document.querySelectorAll('.gallery-item img').forEach(img => {
    img.style.cursor = 'zoom-in';
    const box = img.closest('.gallery-item') || img;
    let tilted = false;
    let resetTimer;

    function doTilt() {
      clearTimeout(resetTimer);
      tilted = true;
      /* Phase 1 — tilt right with depth + lift shadow */
      box.style.transition = 'transform 0.14s cubic-bezier(0.25,0.46,0.45,0.94), box-shadow 0.14s ease';
      box.style.transform  = 'perspective(380px) rotateY(20deg) rotateX(-5deg) scale(0.93)';
      box.style.boxShadow  = '8px 14px 36px rgba(0,0,0,0.65), -2px -4px 18px rgba(74,133,245,0.18)';
      setTimeout(() => {
        /* Phase 2 — spring rebound left, slightly overshoot */
        box.style.transition = 'transform 0.20s cubic-bezier(0.34,1.56,0.64,1), box-shadow 0.20s ease';
        box.style.transform  = 'perspective(380px) rotateY(-11deg) rotateX(2deg) scale(0.97)';
        box.style.boxShadow  = '-5px 10px 28px rgba(0,0,0,0.50)';
        setTimeout(() => {
          /* Phase 3 — spring settle to flat */
          box.style.transition = 'transform 0.28s cubic-bezier(0.34,1.30,0.64,1), box-shadow 0.28s ease';
          box.style.transform  = '';
          box.style.boxShadow  = '';
          resetTimer = setTimeout(() => { tilted = false; }, 1800);
        }, 180);
      }, 145);
    }

    function handleClick() {
      if (!tilted) {
        doTilt();
      } else {
        clearTimeout(resetTimer);
        tilted = false;
        open(img.src, img.alt);
      }
    }

    img.addEventListener('click', handleClick);
    img.addEventListener('touchend', e => { e.preventDefault(); handleClick(); }, { passive: false });
  });
  lb.addEventListener('click', e => { if (e.target === lb || e.target === lbBtn) close(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });
})();

/* ── 3D tilt on screenshot click ── */
document.querySelectorAll('.screen-body img').forEach(img => {
  let busy = false;
  const box = img.closest('.screen-frame') || img;
  function doTilt() {
    if (busy) return; busy = true;
    box.style.transition = 'transform 0.13s ease';
    box.style.transform  = 'perspective(700px) rotateY(18deg) scale(0.95)';
    setTimeout(() => {
      box.style.transform = 'perspective(700px) rotateY(-14deg) scale(0.95)';
      setTimeout(() => {
        box.style.transition = 'transform 0.22s ease';
        box.style.transform  = '';
        setTimeout(() => { busy = false; }, 220);
      }, 130);
    }, 130);
  }
  img.addEventListener('click', doTilt);
  img.addEventListener('touchend', e => { e.preventDefault(); doTilt(); }, { passive: false });
});

/* ── Smooth anchor scroll ── */
document.querySelectorAll('a[href^="#"]').forEach(a => {
  a.addEventListener('click', e => {
    const target = document.querySelector(a.getAttribute('href'));
    if (target) { e.preventDefault(); target.scrollIntoView({ behavior: 'smooth' }); }
  });
});

/* ── Language switcher dropdown ── */
(function () {
  const btn  = document.getElementById('lang-btn');
  const menu = document.getElementById('lang-menu');
  if (!btn || !menu) return;

  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    const isOpen = !menu.hidden;
    menu.hidden = isOpen;
    btn.setAttribute('aria-expanded', String(!isOpen));
  });

  menu.addEventListener('click', e => {
    const opt = e.target.closest('.lang-opt');
    if (!opt) return;
    applyLang(opt.dataset.lang);
    menu.hidden = true;
    btn.setAttribute('aria-expanded', 'false');
  });

  document.addEventListener('click', () => {
    if (!menu.hidden) {
      menu.hidden = true;
      btn.setAttribute('aria-expanded', 'false');
    }
  });

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !menu.hidden) {
      menu.hidden = true;
      btn.setAttribute('aria-expanded', 'false');
      btn.focus();
    }
  });
})();

/* ── Hamburger mobile nav ── */
(function () {
  const hamburger = document.getElementById('hamburger');
  const mobileNav = document.getElementById('mobile-nav');
  if (!hamburger || !mobileNav) return;

  hamburger.addEventListener('click', () => {
    const open = mobileNav.classList.toggle('open');
    hamburger.classList.toggle('open', open);
    hamburger.setAttribute('aria-expanded', String(open));
  });

  mobileNav.querySelectorAll('a').forEach(a => {
    a.addEventListener('click', () => {
      mobileNav.classList.remove('open');
      hamburger.classList.remove('open');
      hamburger.setAttribute('aria-expanded', 'false');
    });
  });

  document.addEventListener('click', e => {
    if (!mobileNav.contains(e.target) && !hamburger.contains(e.target)) {
      mobileNav.classList.remove('open');
      hamburger.classList.remove('open');
      hamburger.setAttribute('aria-expanded', 'false');
    }
  });
})();
