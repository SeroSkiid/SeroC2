/* ══════════════════════════════════════════════════════════════════
   i18n — multi-language support (17 languages, auto-detect)
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
  html.dir  = (code === 'ar') ? 'rtl' : 'ltr';
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
  const mobile = W < 768;

  const renderer = new THREE.WebGLRenderer({ canvas, alpha: false, antialias: false });
  renderer.setPixelRatio(Math.min(devicePixelRatio, mobile ? 1.5 : 2));
  renderer.setClearColor(0x06080f, 1);

  const scene = new THREE.Scene();

  const camera = new THREE.PerspectiveCamera(75, W / H, 0.1, 1000);
  camera.position.z = 1;

  /* ── Parallax — mouse on desktop, touch drag on mobile ────────────── */
  let mx = 0, my = 0, crx = 0, cry = 0;
  if (!mobile) {
    window.addEventListener('mousemove', e => {
      mx = (e.clientX / window.innerWidth  - 0.5) * 0.07;
      my = (e.clientY / window.innerHeight - 0.5) * 0.045;
    }, { passive: true });
  } else {
    /* Mobile: strong tilt — finger position maps to camera angle */
    function applyTouch(touch) {
      mx = (touch.clientX / window.innerWidth  - 0.5) * 0.55;
      my = (touch.clientY / window.innerHeight - 0.5) * 0.38;
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
  ];

  /* ── Nebula wisps — distant colour washes ────────────────────────── */
  function nebula(sz, r1,g1,b1, a1, r2,g2,b2, a2, worldSz, px,py,pz) {
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
    scene.add(sp);
  }

  const ns = mobile ? 0.75 : 1;
  nebula(512, 15,55,200,0.20, 5,22,90,0.06,  230*ns,  90, 35,-300); // blue — upper right
  nebula(512, 70,15,150,0.14, 28,5,80,0.04,  200*ns, -80,-45,-300); // purple — lower left
  nebula(512,  0,90,180,0.10, 0,35,110,0.03, 170*ns,  40,-15,-300); // cyan wash — centre

  /* ── Helper: random point on sphere ──────────────────────────────── */
  function sphPt(r) {
    const phi = Math.acos(2*Math.random()-1), th = Math.random()*Math.PI*2;
    return [r*Math.sin(phi)*Math.cos(th), r*Math.sin(phi)*Math.sin(th), r*Math.cos(phi)];
  }

  /* ── Layer 1 — background field (many tiny dim dots, 1 px) ────────── */
  const BG_N = mobile ? 900 : 2800;
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
  scene.add(new THREE.Points(bgGeo, new THREE.PointsMaterial({
    size: 1, sizeAttenuation: false, vertexColors: true,
    transparent: true, opacity: 0.95, depthWrite: false
  })));

  /* ── Layer 2 — mid stars (2 px, per-star scintillation) ──────────── */
  const MID_N = mobile ? 180 : 500;
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
  scene.add(new THREE.Points(mGeo, new THREE.PointsMaterial({
    size: 2, sizeAttenuation: false, vertexColors: true,
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
    if (kind<0.35)       { rc=255;gc=255;bc=255; }   // white
    else if (kind<0.62)  { rc=200;gc=222;bc=255; }   // blue-white
    else if (kind<0.78)  { rc=155;gc=198;bc=255; }   // blue
    else if (kind<0.90)  { rc=255;gc=245;bc=210; }   // warm white
    else                 { rc=218;gc=182;bc=255; }   // lavender

    const base = mobile ? (1.4+Math.random()*4.2) : (1.8+Math.random()*7.5);
    const gSp  = new THREE.Sprite(new THREE.SpriteMaterial({
      map: glowTex(rc,gc,bc), transparent:true,
      depthWrite:false, blending:THREE.AdditiveBlending, opacity:0
    }));
    gSp.position.set(x,y,z); gSp.scale.set(base,base,1);
    scene.add(gSp);

    // Diffraction spike only for the largest stars
    let spSp = null;
    if (base > (mobile ? 3.5 : 5.5)) {
      spSp = new THREE.Sprite(new THREE.SpriteMaterial({
        map: spikeTex(rc,gc,bc), transparent:true,
        depthWrite:false, blending:THREE.AdditiveBlending, opacity:0
      }));
      spSp.position.set(x,y,z); spSp.scale.set(base*3.0, base*3.0, 1);
      scene.add(spSp);
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

    /* Sky rotation — slow drift like Earth's movement */
    scene.rotation.y += dt * 0.0055;
    scene.rotation.x  = Math.sin(t * 0.014) * 0.018;

    /* Parallax lerp — faster on mobile for snappy response */
    const lf = mobile ? 0.08 : 0.030;
    crx += (my - crx) * lf;
    cry += (mx - cry) * lf;
    camera.rotation.x = crx;
    camera.rotation.y = cry;

    /* Mid-star scintillation — two incommensurable sine waves */
    for (let i = 0; i < MID_N; i++) {
      const s1 = Math.sin(t * mTwk[i*4+1] + mTwk[i*4]);
      const s2 = Math.sin(t * mTwk[i*4+3] + mTwk[i*4+2]);
      const f  = 0.80 + 0.12*s1 + 0.08*s2; // range ≈ 0.60–1.00
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
}, { threshold: 0.07 });
document.querySelectorAll('.reveal').forEach((el, i) => {
  el.style.transitionDelay = (i % 4) * 60 + 'ms';
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
