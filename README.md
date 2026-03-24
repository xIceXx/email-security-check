# Audit Sécurité CLI

Un outil en ligne de commande (CLI) développé en Python permettant d'automatiser des tâches d'audit de sécurité et de gestion de fichiers. 

Ce projet utilise la bibliothèque `Typer` pour la création de l'interface terminal et intègre une analyse heuristique avancée pour la détection de phishing dans les courriels.

## Fonctionnalités principales

* **Gestion de fichiers et permissions** : Parcours de répertoires, lecture de fichiers texte, et mise en quarantaine automatique des fichiers exécutables (`.exe`) avec révocation des droits d'exécution.
* **Analyse de courriels (.eml)** : Décodage natif des fichiers email (multipart, Quoted-Printable) pour éviter les faux positifs liés au formatage.
* **Analyse heuristique (Anti-Phishing)** : 
  * Système de notation (score) basé sur la présence de mots-clés suspects.
  * Extraction intelligente des liens cliquables (attributs `href` dans les balises `<a>`).
  * Vérification de la cohérence entre le domaine de l'expéditeur et les domaines des liens externes.
  * Liste blanche (Whitelist) pour les domaines de confiance (CDN, réseaux sociaux).
* **Vérification SSL/TLS** : Interrogation bas niveau (via `socket` et `ssl`) des domaines extraits pour valider l'authenticité et la sécurité de leurs certificats HTTPS.

## Installation

Ce projet est packagé pour être installable localement via `pip`.

1. Cloner le dépôt ou télécharger les fichiers.
2. Ouvrir un terminal dans le dossier du projet.
3. Créer et activer un environnement virtuel (recommandé) :
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Sur Windows
