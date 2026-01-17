# AFFiNE Navigator

AFFiNE Navigator est un petit serveur **Node.js / Express** qui permet de :
- se connecter à une instance **AFFiNE auto-hébergée**
- lire la base **PostgreSQL** via **SSH + Docker**
- décoder les snapshots **Yjs**
- exposer une API simple pour :
  - lister les workspaces
  - lister les pages
  - afficher le contenu des pages en **Markdown**
  - inspecter les blocs bruts (debug)

Une interface web minimale est fournie pour naviguer visuellement.

---

## ✨ Fonctionnalités

- 🔐 Connexion sécurisée via **SSH** (mot de passe ou clé)
- 🐘 Accès Postgres dans un container Docker AFFiNE
- 🧠 Décodage des snapshots **Yjs**
- 📝 Conversion en **Markdown**
- 🧱 Support des blocs :
  - `affine:page`
  - `affine:paragraph`
  - `affine:note` (edgeless)
  - `affine:surface` (canvas – extraction best-effort du texte)
- 🔍 Endpoint *raw* pour inspection complète
- 🖥 Interface web simple (HTML + JS, sans framework)

---

## 📁 Structure du projet

