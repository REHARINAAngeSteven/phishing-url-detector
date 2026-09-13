# 🤝 Guide de contribution

## Convention de commits

On suit **Conventional Commits** : `type(scope optionnel): description courte`

| Type       | Usage                                              |
| ---------- | --------------------------------------------------- |
| `feat`     | Nouvelle fonctionnalité                              |
| `fix`      | Correction de bug                                    |
| `docs`     | Documentation (README, commentaires, notebook)       |
| `chore`    | Tâches d'entretien (config, dépendances, nettoyage)  |
| `refactor` | Changement de code sans changement de comportement   |
| `test`     | Ajout/modification de tests                          |
| `ci`       | Pipeline CI/CD, Docker                               |

Exemples : `feat: ajouter l'endpoint POST /predict`, `ci: ajouter le pipeline GitHub Actions`

## Convention de branches

Une branche par personne/rôle, créée depuis `main` :

| Branche               | Rôle                              |
| ---------------------- | ---------------------------------- |
| `feature/api`           | Backend / API (FastAPI)            |
| `feature/gradio-ui`     | Frontend / UX (Gradio)              |
| `feature/security`      | Cybersécurité / Analyse des menaces |
| `feature/devops-ci`     | DevOps (Docker + CI/CD)            |
| `feature/tests-deploy`  | Tests / Déploiement                |

Chacun travaille sur sa branche, commit dessus, puis ouvre une **Pull Request vers `main`**. Pas de push direct sur `main`.

# Qui doit commencer en premier ?

**La personne sur l'API (Backend) commence en premier.** C'est le cuisinier du restaurant : tant qu'il n'a rien préparé, personne d'autre n'a rien à servir.

**2 personnes peuvent commencer tout de suite, sans attendre :**
- **Cybersécurité** : améliore la liste des mots/signaux d'arnaque, ne dépend de rien.
- **Tests / Déploiement** : peut déjà vérifier que les calculs de base fonctionnent.

**2 personnes doivent attendre un minimum de l'API :**
- **Interface (Gradio)** : a besoin d'au moins un résultat à afficher à l'écran.
- **DevOps** : a besoin d'un minimum de code à mettre dans sa boîte Docker.

Règle simple : l'API n'a pas besoin d'être terminée pour être partagée. Dès qu'un petit bout marche, on le pousse, pour débloquer les 2 personnes qui attendent.

## Tâches restantes

- [ ] Backend/API : construire et pousser `feature/api` (même une version minimale)
- [ ] Frontend/Gradio : interface sur `feature/gradio-ui`
- [ ] Cybersécurité : listes lexicales + tests sur URLs récentes sur `feature/security`
- [ ] DevOps : `requirements.txt` allégé pour la prod, `Dockerfile`, pipeline GitHub Actions sur `feature/devops-ci`
- [ ] Tests/Déploiement : tests unitaires `feature_extractor.py`, tests d'intégration API, déploiement Hugging Face Spaces sur `feature/tests-deploy`