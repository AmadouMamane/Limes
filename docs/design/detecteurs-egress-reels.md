# limes — les VRAIS détecteurs egress (admission-grade) : spec + prompt

> 2026-07-24 · Repo `limes`. **Remplace les doubles de test par de vrais détecteurs admis.** La v0.4 a la machinerie (couture outbound, rédaction vérifiée) mais **zéro détecteur de fuite réel** — seul `injection` (entrant) est admis. Ce chantier livre `pii-egress` et `secrets-egress` **pour de vrai**, sous ADR 0003. Au bout : limes protège réellement dans les deux sens, la couture outbound se remplit, le README passe honnêtement de « 1 détecteur » à « 3 ».

## 0. Ce qui est le produit ici (à lire avant tout)

Le **code** d'un détecteur egress (regex + Luhn + mod-97 + préfixes de clés) est trivial et se fait en une heure. **Ce n'est PAS le livrable.** Le livrable, c'est **l'admission** (ADR 0003), et c'est du travail d'**éval et de données**, pas de plomberie :

- un **corpus positif** (ce qu'il faut détecter),
- un **corpus bénin** (les sosies qu'il ne faut PAS lever — c'est lui qui prouve la précision),
- un **contrôle nul** (le harnais tourne détecteur débranché : le score à battre),
- une **matrice de confusion publiée par catégorie** (F1 / FP / FN, datée, ratés documentés).

Le gabarit existe et fait foi : le détecteur `injection` (F1 0.86 sur 33 attaques + 8 bénins, battant la baseline 0.80, matrice au README). **Reproduis cette rigueur, pas juste des regex.** Un détecteur qui ne bat pas mesurablement le contrôle nul n'entre pas.

## 1. Contrainte de données (non négociable) : corpus SYNTHÉTIQUE uniquement

Aucune vraie PII, aucun vrai secret dans un dépôt public. Le corpus est **des vecteurs de test / synthétiques** par construction :
- PAN : les numéros de test standard (`4242 4242 4242 4242` & co, Luhn-valides, jamais réels).
- IBAN : exemples checksum-valides fictifs (docs ECBS / RFC).
- Email : `@example.com` / `@example.org`.
- Clés API : **formats** de test / révoqués / d'exemple (jamais une clé vive).
- Clés privées PEM : générées à la volée pour les tests.
- JWT : tokens auto-signés de test.

C'est légitime : on mesure la détection de **format**, pas de la donnée réelle. Un ADR (§7) fige cette règle pour qu'aucun contributeur n'ajoute de vraie donnée plus tard.

## 2. `pii-egress` — catégories fixes, chacune avec sa matrice

- **PAN** (Luhn), **IBAN** (mod-97), **email**, **téléphone** (FR/DE + international), **NIR** (FR).
- **Corpus bénin obligatoire** (le piège FP) : un numéro de commande à 16 chiffres qui **échoue Luhn**, un identifiant interne en forme d'IBAN qui **échoue mod-97**, un email tronqué invalide, un numéro qui n'est pas un téléphone. Chacun **ne doit pas** lever.
- **Baseline à battre** : `apply_output_guard` de Tessera (pin 86bf21dd, lecture seule), **mesuré sur le même corpus**. Relève son chiffre avant de commencer ; publie F1(pii-egress) à côté.

## 3. `secrets-egress` — haute précision préfixée uniquement

- Clés API à préfixe connu (AWS `AKIA…`, OpenAI `sk-…`, GitHub `ghp_/gho_…`, Stripe `sk_live_…`, Google, Slack `xox…`), clés privées **PEM**, **JWT** (3 segments base64url).
- **Reporté** : secrets génériques à haute entropie (trop de FP sans contexte — un UUID, un hash git, un blob base64 ne sont pas des secrets). Documenté dans « ce que ça ne fait pas ».
- **Corpus bénin** : UUID, hash git 40-hex, base64 anodin, couleur hex — ne doivent pas lever.
- **Baseline** : pas de guard secrets côté Tessera (probable) → le **contrôle nul EST la baseline**. Dis-le au README, ne fabrique pas une comparaison qui n'existe pas.

## 4. Intégrité du grader (leçon `injection`, obligatoire)

- **Aucun token contenu dans l'entrée** ne compte comme preuve de détection (un grader qui « voit » le PAN dans son propre input triche).
- Le **témoin, c'est la différence contre le contrôle nul**, jamais un champ `model:`/`detector:` dans un rapport.
- Ratés **documentés avec leur cause**, jamais cachés.

## 5. Bout-en-bout : la couture se remplit pour de vrai

Le vrai `pii-egress` enregistré (entry point) est consommé par la jambe outbound → un **PAN de test dans un résultat de `tools/call`** est détecté, puis **rédigé** par la machinerie existante, **à travers le proxy** (stdio ET http). C'est la preuve que la couture, vide en v0.4, produit maintenant un verdict avec un vrai témoin — pas un double.

## 6. Anti-périmètre

Catégories **fixes** (pas de PII/secret configurable) · corpus **synthétique uniquement** · pas d'entropie générique · pas de détecteur LLM-judge · pas de dépendance modèle · les détecteurs ne touchent **ni cœur ni pipeline ni transports**. Les doubles de test restent, s'ils servent encore, **uniquement** comme fixtures — jamais enregistrés comme détecteurs.

## 7. Definition of done

- `make gate` vert (ruff + `mypy --strict` + pytest).
- **`pii-egress` admis** : corpus positif + bénin + contrôle nul + **matrice par catégorie au README** ; **bat/égale `apply_output_guard`** (chiffre publié) ; PAN Luhn-valide de test détecté, 16-chiffres non-Luhn **non** détecté.
- **`secrets-egress` admis** : idem, baseline = contrôle nul (dit au README) ; clé préfixée de test détectée, UUID/hash git **non** détectés.
- **Enregistrés** (entry points), consommés par la couture outbound.
- **Bout-en-bout** : PAN de test dans un `tools/call` result → détecté → rédigé, prouvé via proxy **stdio ET http**, avec run de contrôle (le serveur réel a bien renvoyé le PAN sans détecteur).
- **Fail-closed** : contenu illisible → `CannotSay`, jamais `Allow`.
- **Zéro donnée brute** dans un record (spans rédigés seulement) — test qui balaie le corpus dans les records/annotations/JSONL.
- **Grader intègre** : aucun token de l'entrée ne compte comme preuve ; contrôle nul publié.
- **Frontière** : cliquet « cœur/pipeline/transports inchangés » vu rouge sous mutation.
- **README/CHANGELOG** : « 1 détecteur » → **« 3 détecteurs »** honnête, matrices datées, ratés documentés.
- **ADR 0009** — « corpus egress : synthétique/test-only, admission par catégorie » (fige la règle données du §1).

---

## Prompt d'implémentation (session dédiée, repo `limes`)

```
Projet limes — session d'IMPLÉMENTATION : les VRAIS détecteurs egress.
Contexte : la v0.4 a la machinerie outbound (couture + rédaction vérifiée) mais AUCUN
détecteur de fuite RÉEL — pii/secret sont des DOUBLES DE TEST. Livre-les pour de vrai,
sous ADR 0003. Lis d'abord : le détecteur `injection` (ton GABARIT : corpus + contrôle
nul + matrice), le Detector Protocol, la couture outbound, la rédaction, et
apply_output_guard côté Tessera (pin 86bf21dd, lecture seule) = baseline pii.

LE LIVRABLE N'EST PAS LE CODE, C'EST L'ADMISSION. Le code (regex/Luhn/mod-97/préfixes)
est trivial. Le produit = corpus positif + corpus BÉNIN de sosies + contrôle nul +
matrice par catégorie publiée. Un détecteur qui ne bat pas mesurablement le contrôle
nul n'entre pas.

DONNÉES : corpus SYNTHÉTIQUE / vecteurs de test UNIQUEMENT (PAN 4242…, IBAN d'exemple,
@example.com, formats de clés révoquées/exemple, PEM générés, JWT auto-signés). JAMAIS
de vraie PII/secret. ADR 0009 fige cette règle.

ORDRE, EN SÉRIE (chacun landé + gate vert + preuve avant le suivant) :
1) pii-egress : PAN(Luhn), IBAN(mod-97), email, téléphone(FR/DE/intl), NIR. Corpus bénin
   (16-chiffres non-Luhn, faux IBAN, etc.). Bat apply_output_guard, mesuré, publié.
2) secrets-egress : clés préfixées (AWS/OpenAI/GitHub/Stripe/Google/Slack), PEM, JWT.
   Entropie générique REPORTÉE (documentée). Corpus bénin (UUID, hash git, base64, hex).
   Baseline = contrôle nul (dit au README).

INTÉGRITÉ GRADER : aucun token de l'entrée ne compte comme preuve ; témoin = écart au
contrôle nul ; ratés documentés avec cause.

BOUT-EN-BOUT : détecteur enregistré (entry point) → consommé par la couture outbound →
un PAN de test dans un tools/call result est détecté PUIS rédigé, prouvé via proxy stdio
ET http, avec run de contrôle (serveur renvoie bien le PAN sans détecteur).

ANTI-PÉRIMÈTRE : catégories fixes, corpus synthétique only, pas d'entropie générique,
pas de LLM-judge, détecteurs ne touchent ni cœur ni pipeline ni transports ; les doubles
restent au plus des fixtures, jamais enregistrés.

DoD (chaque item PROUVÉ) : gate vert ; pii-egress & secrets-egress admis (corpus+contrôle
nul+matrice par catégorie au README), pii bat apply_output_guard (publié), PAN test
détecté / 16-non-Luhn non, clé test détectée / UUID non ; enregistrés + consommés ;
bout-en-bout via stdio ET http + run de contrôle ; fail-closed ; zéro donnée brute dans
un record (test balaie le corpus) ; cliquet frontière vu rouge ; README/CHANGELOG « 1 →
3 détecteurs » honnête ; ADR 0009. Conventions repo (Python 3.12/uv/ruff/mypy --strict/
pytest, Conventional Commits, pas de notebooks). Montre le diff + la preuve de chaque item.
```

---

## Petit prompt (lancer Opus)

```
Repo `limes`. Livre les VRAIS détecteurs egress selon docs/design/detecteurs-egress-reels.md
(copie-la dans le repo). Contexte : pii/secret sont des DOUBLES aujourd'hui ; livre-les
admis sous ADR 0003. LE LIVRABLE = L'ADMISSION (corpus positif + bénin de sosies + contrôle
nul + matrice par catégorie), pas le code. Gabarit = le détecteur injection. Corpus
SYNTHÉTIQUE/test-only (jamais de vraie donnée ; ADR 0009). En série : 1) pii-egress
(PAN Luhn/IBAN mod-97/email/tel/NIR, bat apply_output_guard mesuré) 2) secrets-egress
(clés préfixées/PEM/JWT, entropie générique reportée, baseline=contrôle nul). Grader
intègre (aucun token de l'entrée ne compte). Bout-en-bout : détecteur enregistré → couture
outbound → PAN test détecté puis rédigé via proxy stdio ET http, avec run de contrôle.
Fail-closed. Zéro donnée brute dans les records. Cliquet frontière vu rouge. README/CHANGELOG
« 1 → 3 détecteurs ». Conventions repo. Diff + preuve de chaque item DoD.
```
