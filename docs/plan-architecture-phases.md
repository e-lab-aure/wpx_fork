# Architecture en phases : collecte / validation / artefact / enrichissement WPScan / rapport

## Objectif

Séparer complètement la **collecte** (WAF bypass, détection WordPress/plugins/thèmes/users) de
l'**enrichissement WPScan** (vulnérabilités connues), pour pouvoir :

- lancer une collecte sans jamais appeler l'API WPScan (pas de clé, API indisponible, quota
  épuisé, hors ligne après coup) ;
- sauvegarder un artefact réutilisable ;
- enrichir et régénérer le rapport plus tard, **sans rescanner la cible**, à partir du seul
  artefact local.

Contrainte non négociable : **aucun appel WPScan pendant la collecte**. L'ordre est strictement
`TARGET → COLLECT → VALIDATE → ARTIFACT → WPSCAN ENRICHMENT → REPORT`, jamais l'inverse.

Fork de [greg-randall/wpx](https://github.com/greg-randall/wpx) — `upstream` est configuré comme
remote sur ce dépôt pour pouvoir récupérer les évolutions futures. Compatibilité maximale avec
l'architecture existante : petits modules, changements isolés, pas de réécriture inutile.

---

## État actuel (vérifié, lecture complète du dépôt — ~3300 lignes)

```
CURRENT FLOW
────────────
wpx.py::main() / _run()
   ↓
WPXData         — télécharge/charge les métadonnées WPScan (finders, slugs, config_backups)
   ↓
WPXCore.bypass_waf()           — Camoufox : page.goto(url, wait_until="networkidle"),
                                  AUCUN timeout explicite (défaut Playwright 30000ms)
   ↓
WPXCore.setup_mirror_session() — session curl_cffi qui rejoue cookies + UA du navigateur
   ↓
WPXFinder                      — TOUTE la collecte (headers, version WP, thèmes, plugins
                                  passifs, brute-force plugins, versions, users, config
                                  backups). État accumulé en attributs d'instance mutables
                                  (self.found_plugins, self.wp_version, self.theme, …)
   ↓
WPXVulnerability.get_vulnerabilities()   ← wpx.py lignes 304-309, DANS _run(), juste après
                                            la collecte, un appel par plugin trouvé, SI
                                            --api-key est fourni. Aucune séparation.
   ↓
Impression terminal (print_finding/…)    — inline dans _run() (lignes 311-594), mélange
                                            résultats de collecte et résultats WPScan dans
                                            les mêmes blocs d'affichage. Pas de module
                                            « rapport » séparé, pas d'export JSON.
```

Fichiers et responsabilités actuelles :

| Fichier | Rôle | Constat |
|---|---|---|
| `wpx.py` | CLI + orchestration + rapport terminal | Tout mélangé : parsing, pipeline, appel WPScan, affichage |
| `wpx_core.py` | WAF bypass (Camoufox) + session curl_cffi | `bypass_waf()` : `networkidle` sans timeout, cause du bug rapporté |
| `wpx_finder.py` (872 lignes) | Toute la détection | Classe à état mutable, aucune sérialisation |
| `wpx_data.py` | Métadonnées WPScan (finders, slugs, backups) | OK tel quel |
| `wpx_vulnerability.py` | Client API WPScan | **Déjà isolé** : `get_vulnerabilities(item_type, slug)`, aucun couplage au Finder. Le point « module WPScan dédié » est déjà acquis — il ne reste qu'à changer *quand* il est appelé |
| `wpx_output.py` | Impression terminal formatée | OK tel quel, réutilisable par le futur module rapport |
| `tests/` | pytest + pytest-mock, 4 fichiers, fixtures dans `conftest.py` | À étendre, pas à réécrire |

---

## Flux proposé

```
NEW FLOW
────────
wpx scan --collect-only TARGET     wpx enrich <scan-dir>          wpx report <scan-dir>
        ↓                                  ↓                              ↓
   COLLECT                         charge inventory.json          charge scan.json +
   (WPXFinder, inchangé)                   ↓                      vulnerability.json (si présent)
        ↓                          WPXVulnerability.enrich()              ↓
   VALIDATE (nouveau)                      ↓                      impression terminal — module
   normalise found_plugins/       sauvegarde vulnerability.json   séparé, plus mêlé à la collecte
   theme/wp_version en             (AUCUNE requête vers la cible)
   inventaire structuré,
   confidence + evidence
        ↓
   SAVE (scan.json + inventory.json — aucun appel WPScan possible à ce stade)

wpx scan TARGET  =  collect + validate + save + enrich + report à la suite
                     (comportement actuel préservé, juste réorganisé en étapes rejouables)
```

---

## Points d'attention identifiés (à trancher avant/pendant l'implémentation)

- **`--full-scan`** génère 50k+ requêtes de brute-force : l'inventaire normalisé (léger) doit
  rester distinct des preuves brutes volumineuses (corps HTTP), avec un budget de taille par
  preuve — sinon l'artefact d'un scan complet devient ingérable.
- **`WPXFinder`** garde tout en attributs d'instance mutables. Plutôt que de le réécrire en
  profondeur, ajouter une méthode `to_inventory()` qui sérialise son état accumulé en JSON
  normalisé — conforme à « pas de réécriture inutile ».
- Le rapport texte actuel (riche, déjà bien fait) est extrait tel quel dans un nouveau
  `wpx_report.py`, adapté pour lire depuis `scan.json`/`vulnerability.json` au lieu des
  attributs live du Finder — pas une réécriture depuis zéro.
- Versions inconnues (`version = null`/`"Unknown"`) : jamais inventées, conservées comme telles ;
  la décision d'interroger ou non WPScan pour un composant sans version se prend explicitement
  dans `WPXScanEnricher`, pas par défaut.
- Doublons de plugins/thèmes détectés par plusieurs sources : dédupliqués avant l'enrichissement
  (une seule requête WPScan par slug, jamais une par source de détection).

---

## Étapes (chacune vérifiée avant de passer à la suivante — pas de refactor massif en un bloc)

- [x] **Étape 1 — Analyse** (faite, ci-dessus).
- [x] **Étape 2 — Corriger `networkidle`** (`wpx_core.py::bypass_waf`) — faite.
  - `wait_until="domcontentloaded"`, timeout configurable (défaut 60000ms).
  - Ne pas juste avaler l'exception `PlaywrightTimeoutError` : sur timeout, vérifier si la page
    est malgré tout exploitable (URL courante, contenu, indicateurs WAF/challenge, DOM
    disponible) avant de déclarer l'échec définitif.
  - Test de régression si l'architecture de test le permet (mock de `page.goto`).
- [x] **Étape 3 — Inventaire normalisé + artefact de collecte** — faite.
  - Modèle interne (`wordpress`, `plugins[]`, `themes[]`, chacun avec `confidence`, `evidence`) —
    valeurs uniquement issues des résultats réels, jamais inventées.
  - `WPXFinder.to_inventory()` (ou fonction équivalente) qui sérialise l'état accumulé.
  - Artefact sur disque (structure à caler sur ce qui existe déjà si possible, sinon proposition
    `scans/<scan-id>/{scan.json,inventory.json,evidence.json,http/,screenshots/}`).
- [x] **Étape 4 — Séparer WPScan de la collecte** — faite.
  - Retirer l'appel `WPXVulnerability` de `_run()` / de la phase de collecte.
  - `--collect-only` (ou option équivalente) : ne construit jamais `WPXVulnerability`, ne
    consomme aucune requête WPScan, fonctionne sans clé / hors ligne / API indisponible.
- [x] **Étape 5 — `wpx enrich <scan-dir>`** — faite.
  - Charge uniquement `inventory.json`, **aucun accès à la cible**.
  - `WPScanEnricher` (`integrations/wpscan.py` ou emplacement cohérent) : reçoit un inventaire
    déjà établi, ne découvre rien lui-même, écrit `vulnerability.json`.
  - Composants sans version connue / doublons : pas de requête inutile (dédupliqués en amont).
  - Erreur WPScan (indisponible, quota) : n'efface jamais l'artefact existant, `enrich` reste
    rejouable plus tard (`{"status": "failed", "error": "..."}`, jamais une exception qui
    corrompt le scan).
- [x] **Étape 6 — `wpx report <scan-dir>`** — faite.
  - Nouveau `wpx_report.py`, lit `scan.json` (+ `vulnerability.json` si présent).
  - Distingue clairement **observation** (ce que la collecte a vu) et **enrichissement**
    (ce que WPScan indique) — jamais une vulnérabilité WPScan présentée comme preuve
    d'exploitation réussie.
  - Génère un rapport même sans WPScan (`WPScan enrichment: unavailable`).
- [x] **Étape 7 — Tests** — faite. Les 7 tests requis sont chacun explicitement présents dans
  `tests/test_offline_guarantees.py` (un test par point, docstring citant l'exigence), en plus
  de leur couverture croisée dans `test_collect_only.py`/`test_enricher.py`/
  `test_inventory_artifact.py`/`test_core.py`.
  1. `collect-only` ne fait aucun appel WPScan.
  2. `enrich` ne fait aucune requête réseau vers la cible.
  3. L'enrichissement utilise uniquement l'inventaire sauvegardé.
  4. Les doublons ne génèrent pas de requêtes WPScan inutiles.
  5. Une erreur WPScan ne détruit pas l'artefact de scan.
  6. Un scan existant peut être enrichi plusieurs fois.
  7. Le changement `networkidle → domcontentloaded` fonctionne (Étape 2).

  Bonus (bug trouvé en écrivant ces tests) : `wpx_output` garde `_quiet`/`_output_file` en
  variables globales de module, réglées par `init_output()`. Les tests des sous-commandes CLI
  (`_run_enrich`/`_run_report`) appellent `init_output(quiet=True)` en effet de bord, ce qui
  fuitait sur les tests suivants dans le même process et supprimait silencieusement leur sortie
  `print_info`/`print_status`. Corrigé par une fixture `autouse` dans `tests/conftest.py` qui
  réinitialise cet état avant/après chaque test.
- [x] **Étape 8 — README** — faite.
  - Section « Collection, Enrichment & Reporting (offline replay) ».
  - `wpx scan --collect-only URL`, `wpx enrich <scan-dir>`, `wpx report <scan-dir>`.
  - Rappel explicite : `enrich` ne rescanne jamais la cible, dépend des conditions/limites de
    l'API WPScan, ne doit jamais servir à contourner son quota ou ses CGU.

Après chaque étape : vérifier que les fonctionnalités existantes ne sont pas cassées avant de
passer à la suivante.

## CLI visée

```bash
wpx scan --collect-only https://target.example      # collecte seule, jamais d'appel WPScan
wpx enrich scans/<scan-id>/                          # enrichissement offline, jamais de requête cible
wpx report scans/<scan-id>/                          # rapport, avec ou sans enrichissement
wpx scan https://target.example                      # pipeline complet (comportement actuel)
```

À adapter à la syntaxe CLI existante (`argparse` dans `wpx.py`) si une forme plus cohérente avec
l'existant se présente en implémentant.

## Ne pas faire

- Pas de mécanisme pour contourner les limites/quotas/CGU de l'API WPScan.
- Ne jamais transformer l'API WPScan en base de données locale de vulnérabilités.
- Ne supprimer aucune fonctionnalité existante sans le dire explicitement ici.

---

## Bilan final (les 8 étapes sont terminées)

### Fichiers modifiés/créés

| Fichier | Statut | Rôle |
|---|---|---|
| `wpx_core.py` | Modifié | `networkidle` → `domcontentloaded`, timeout configurable, `_page_seems_usable()` |
| `wpx_finder.py` | Modifié | `to_inventory()` (+ méthodes privées de sérialisation par section) |
| `wpx_artifact.py` | **Créé** | Persistance `scan.json`/`inventory.json`/`vulnerability.json` |
| `wpx_enricher.py` | **Créé** | `WPScanEnricher` — enrichissement offline, un seul module |
| `wpx_report.py` | **Créé** | `print_report()` — rapport terminal, observation vs enrichissement |
| `wpx.py` | Modifié | CLI (`--collect-only`, `--nav-timeout`, `--scan-dir`, `--no-artifact`), sous-commandes `enrich`/`report`, pipeline `_run()` réorganisé en étapes rejouables |
| `wpx_vulnerability.py`, `wpx_data.py`, `wpx_output.py` | Inchangés | Déjà conformes (client API isolé, données WPScan, impression terminal réutilisable) |
| `tests/test_core.py` | **Créé** | Étape 2 |
| `tests/test_inventory_artifact.py` | **Créé** | Étape 3 |
| `tests/test_collect_only.py` | **Créé** | Étapes 4, 5, 6 (CLI `enrich`/`report`) |
| `tests/test_enricher.py` | **Créé** | Étape 5 |
| `tests/test_report.py` | **Créé** | Étape 6 |
| `tests/test_offline_guarantees.py` | **Créé** | Étape 7 — mapping direct des 7 tests requis |
| `tests/conftest.py` | Modifié | Fixture `autouse` de reset de l'état global `wpx_output` |
| `README.md` | Modifié | Section Collection/Enrichment/Reporting, tables d'options à jour |

### Avant / après

**Avant** : un seul flux `_run()` qui collecte, appelle WPScan (si `--api-key`) et imprime le
tout dans le même bloc, sans artefact sur disque, sans étape rejouable.

**Après** :
```
wpx scan --collect-only URL   →  scan.json + inventory.json (jamais d'appel WPScan)
wpx enrich <scan-dir> --api-key KEY  →  vulnerability.json (jamais d'accès à la cible)
wpx report <scan-dir>         →  rapport terminal (aucun accès réseau)
wpx scan URL                  =  les trois étapes à la suite (comportement par défaut inchangé)
```

### Nouvelles commandes CLI

- `wpx.py -u URL --collect-only [--scan-dir DIR] [--no-artifact]`
- `wpx.py -u URL --nav-timeout MS`
- `wpx.py enrich SCAN_DIR --api-key KEY`
- `wpx.py report SCAN_DIR`

### Tests

- 137 tests passent (72 avant l'étape 2, 65 nouveaux répartis sur les étapes 2 à 7).
- Vérifiés par des tests de bout en bout réels (serveur HTTP local, `--no-browser`) à chaque
  étape : collecte seule, `enrich` isolé, `report` isolé, pipeline complet — dans un
  environnement où le réseau vers WPScan est bloqué par le sandbox, confirmant que
  l'indisponibilité de WPScan ne bloque jamais la collecte ni ne corrompt l'artefact.
- Bug de fuite d'état entre tests trouvé et corrigé à l'étape 7 (voir ci-dessus).

### Points restants ouverts

- `docs/plan-architecture-phases.md` est forcé dans le suivi git malgré `*.md` dans
  `.gitignore` (voir commit de l'étape 1) — décision à prendre : garder le forçage, exclure ce
  fichier précisément du `.gitignore`, ou replier son contenu dans le README une fois la
  fonctionnalité stabilisée.
- L'inventaire normalisé ne budgétise pas encore la taille des preuves brutes pour
  `--full-scan` (point d'attention identifié dès l'étape 1) — non bloquant aujourd'hui car
  `to_inventory()` ne stocke que des chaînes courtes (slugs, URLs, extraits de match), mais à
  surveiller si des preuves plus volumineuses sont ajoutées plus tard.
- Pas de sous-commande `scan` explicite : le pipeline complet reste `wpx.py -u URL` (compatible
  avec l'usage existant) plutôt que `wpx.py scan URL` comme esquissé dans le CLI visé
  ci-dessus — changement mineur pour rester compatible avec la syntaxe déjà documentée/utilisée.

### Installation / usage

Aucun changement de dépendances ni d'installation. Les nouvelles commandes utilisent uniquement
des modules déjà présents dans `requirements.txt`/`pyproject.toml`.
