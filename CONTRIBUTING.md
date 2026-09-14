# 🤝 Guide de contribution

## Convention de commits

On suit **Conventional Commits** : `type(scope optionnel): description courte`

| Type       | Usage                                              |
| ---------- | -------------------------------------------------- |
| `feat`     | Nouvelle fonctionnalité                            |
| `fix`      | Correction de bug                                  |
| `docs`     | Documentation (README, commentaires, notebook)     |
| `chore`    | Tâches d'entretien (config, dépendances, nettoyage) |
| `refactor` | Changement de code sans changement de comportement |
| `test`     | Ajout/modification de tests                        |
| `ci`       | Pipeline CI/CD, Docker                             |

Exemples : `feat(api): ajouter l'endpoint POST /predict`, `fix(predict): corriger le warning feature names`

## Convention de branches

Une branche par personne/rôle, créée depuis `main` :

| Branche               | Rôle                                     |
| --------------------- | ---------------------------------------- |
| `feature/predict`     | Feature extraction + `src/predict.py`   |
| `feature/api`         | Backend / API                           |
| `feature/gradio-ui`   | Interface web (Gradio ou autre)         |
| `feature/tests`       | Tests unitaires + documentation         |
| `feature/deploy`      | Déploiement Hugging Face                |

Chacun travaille sur sa branche, commit dessus, puis ouvre une **Pull Request vers `main`**. Pas de push direct sur `main`.

## Qui doit commencer en premier ?

**La personne sur l'API (Backend) commence en premier.** C'est le cuisinier du restaurant : tant qu'il n'a rien préparé, personne d'autre n'a rien à servir.

**Peuvent commencer tout de suite :**
- **Feature extraction** (`src/predict.py`) : amélioration du code existant, correction du warning, ajout CLI.
- **Tests** : tests unitaires de `feature_extractor.py`, ne dépendent de rien.

**Doivent attendre un minimum de l'API :**
- **Interface web** : a besoin d'au moins une API qui tourne pour afficher des résultats. Peut commencer en "mode mocké" (résultats factices).
- **Déploiement** : a besoin d'une interface fonctionnelle.

Règle simple : l'API n'a pas besoin d'être terminée pour être partagée. Dès qu'un petit bout marche, on le pousse, pour débloquer les 2 personnes qui attendent.

## Tâches restantes

- [ ] **Feature extraction** : `src/predict.py` (fix warning, CLI) sur `feature/predict`
- [ ] **Backend/API** : construire et pousser `feature/api` (même version minimale) ← **PRIORITÉ**
- [ ] **Interface web** : interface Gradio ou équivalent sur `feature/gradio-ui` (mode mocké autorisé au début)
- [ ] **Tests** : tests unitaires `feature_extractor.py`, tests d'intégration API sur `feature/tests`
- [ ] **Déploiement** : Hugging Face Spaces sur `feature/deploy`
