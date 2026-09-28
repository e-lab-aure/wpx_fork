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
- [ ] **Étape 6 — `wpx report <scan-dir>`**
  - Nouveau `wpx_report.py`, lit `scan.json` (+ `vulnerability.json` si présent).
  - Distingue clairement **observation** (ce que la collecte a vu) et **enrichissement**
    (ce que WPScan indique) — jamais une vulnérabilité WPScan présentée comme preuve
    d'exploitation réussie.
  - Génère un rapport même sans WPScan (`WPScan enrichment: unavailable`).
- [ ] **Étape 7 — Tests**
  1. `collect-only` ne fait aucun appel WPScan.
  2. `enrich` ne fait aucune requête réseau vers la cible.
  3. L'enrichissement utilise uniquement l'inventaire sauvegardé.
  4. Les doublons ne génèrent pas de requêtes WPScan inutiles.
  5. Une erreur WPScan ne détruit pas l'artefact de scan.
  6. Un scan existant peut être enrichi plusieurs fois.
  7. Le changement `networkidle → domcontentloaded` fonctionne (Étape 2).
- [ ] **Étape 8 — README**
  - Section Collection / Enrichment / Reporting / Offline replay.
  - `wpx scan --collect-only TARGET`, `wpx enrich <scan-dir>`, `wpx report <scan-dir>`.
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
