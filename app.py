import email
import os
import re
import shutil
import socket
import ssl
import stat
from email import policy
from pathlib import Path

import typer

app = typer.Typer(help="Outil d'audit de sécurité et de gestion de fichiers")


def verifier_certificat_https(domaine: str) -> bool:
    """
    Tente de se connecter au domaine sur le port HTTPS (443).
    Renvoie True si le certificat est valide, False s'il est invalide ou inaccessible.
    """
    contexte = ssl.create_default_context()
    
    try:
        with socket.create_connection((domaine, 443), timeout=3) as sock:
            with contexte.wrap_socket(sock, server_hostname=domaine) as ssock:
                return True
    except ssl.SSLError:
        return False
    except (socket.timeout, socket.error):
        return False


@app.command()
def lister(dossier: str = typer.Argument(".", help="Le dossier à lister")):
    """
    Affiche la chaîne 'test' puis liste le contenu d'un répertoire donné.
    """
    print("test")
    
    try:
        fichiers = os.listdir(dossier)
        print(f"Fichiers dans {dossier} :")
        for fichier in fichiers:
            print(f"- {fichier}")
    except FileNotFoundError:
        print("Dossier introuvable.")


@app.command()
def analyser(dossier: Path = typer.Argument(".", help="Le dossier à scanner")):
    """
    Parcourt et affiche le contenu des fichiers .TXT présents dans le dossier.
    """
    print(f"Lecture des fichiers texte dans : {dossier.absolute()}")
    
    fichiers = list(dossier.glob("*.txt"))
    if not fichiers:
        print("Aucun fichier .txt trouvé.")
        return

    for fichier in fichiers:
        print(f"\nFichier : {fichier.name}")
        contenu = fichier.read_text(encoding="utf-8", errors="ignore")
        print(f"--- Contenu ---\n{contenu}\n---------------")


@app.command()
def quarantaine(dossier: Path = typer.Argument(".", help="Le dossier à nettoyer")):
    """
    Recherche les fichiers .EXE, les déplace dans un dossier de quarantaine 
    et supprime leurs droits d'exécution.
    """
    print(f"Mise en quarantaine des exécutables dans : {dossier.absolute()}")
    
    fichiers_exe = list(dossier.glob("*.exe"))
    if not fichiers_exe:
        print("Aucun danger détecté (pas de .exe).")
        return

    dossier_q = dossier / "quarantine"
    dossier_q.mkdir(exist_ok=True)

    for fichier in fichiers_exe:
        destination = dossier_q / fichier.name
        shutil.move(str(fichier), str(destination))
        
        mode_actuel = os.stat(destination).st_mode
        os.chmod(destination, mode_actuel & ~stat.S_IEXEC)
        
        print(f"[{fichier.name}] déplacé et sécurisé.")


@app.command()
def scan_emails(dossier: Path = typer.Argument(".", help="Le dossier contenant les fichiers .eml")):
    """
    Analyse les fichiers .eml pour détecter des tentatives de phishing ou de spam.
    Évalue les mots-clés, la cohérence des liens HTML et la validité des certificats HTTPS.
    """
    mots_suspects = ["gagné", "loterie", "héritage", "urgent", "cliquez ici", "cadeau", "promo", "code"]
    domaines_de_confiance = [
        "instagram.com", "facebook.com", "linkedin.com", "twitter.com", 
        "youtube.com", "helloasso.com", "lydia-app.com", "discord.gg", 
        "linktr.ee", "google.com", "awstrack.me"
    ]
    
    print(f"Analyse des emails dans : {dossier.absolute()}\n")

    for fichier in dossier.glob("*.eml"):
        try:
            with open(fichier, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
            
            contenu_lower = ""
            domaines_liens_bruts = []

            def extraire_liens(corps, type_contenu):
                if not corps: return []
                corps_str = str(corps).lower()
                if type_contenu == "text/html":
                    return re.findall(r'<a\b[^>]*?href\s*=\s*["\']?\s*https?://(?:www\.)?([\w\.-]+)', corps_str)
                elif type_contenu == "text/plain":
                    return re.findall(r"https?://(?:www\.)?([\w\.-]+)", corps_str)
                return []

            if msg.is_multipart():
                for part in msg.walk():
                    if part.is_multipart():
                        continue
                    
                    type_mime = part.get_content_type()
                    if type_mime in ["text/plain", "text/html"]:
                        try:
                            texte_partie = part.get_content()
                            if texte_partie:
                                contenu_lower += str(texte_partie).lower()
                                domaines_liens_bruts.extend(extraire_liens(texte_partie, type_mime))
                        except Exception:
                            pass 
            else:
                type_mime = msg.get_content_type()
                if type_mime in ["text/plain", "text/html"]:
                    texte_partie = msg.get_content()
                    if texte_partie:
                        contenu_lower += str(texte_partie).lower()
                        domaines_liens_bruts.extend(extraire_liens(texte_partie, type_mime))
            
            score = 0
            raisons = []

            trouves = [m for m in mots_suspects if m in contenu_lower]
            if trouves:
                points_mots = len(trouves) * 1
                score += points_mots
                raisons.append(f"[+{points_mots}] Mots trouvés : {', '.join(trouves)}")

            expediteur_brut = msg.get('From', '')
            match_from = re.search(r"@([\w\.-]+)", expediteur_brut)
            
            if match_from:
                domaine_expediteur = match_from.group(1).lower()
                mots_domaine = domaine_expediteur.split('.')
                domaine_principal_exp = ".".join(mots_domaine[-2:]) if len(mots_domaine) >= 2 else domaine_expediteur
                
                for domaine_lien in set(domaines_liens_bruts):
                    if len(domaine_lien) < 4 or "." not in domaine_lien:
                        continue
                        
                    est_de_confiance = any(trusted in domaine_lien for trusted in domaines_de_confiance)
                    
                    if not est_de_confiance and domaine_principal_exp not in domaine_lien:
                        score += 5
                        raisons.append(f"[+5] Lien cliquable externe suspect : '{domaine_lien}'")

                        if not verifier_certificat_https(domaine_lien):
                            score += 3
                            raisons.append(f"[+3] Certificat HTTPS invalide ou absent : '{domaine_lien}'")

            if score >= 5:
                typer.secho(f"ALERT : {fichier.name} (Score: {score})", fg=typer.colors.RED, bold=True)
                for r in raisons:
                    print(f"   -> {r}")
            elif score >= 3:
                typer.secho(f"Suspect : {fichier.name} (Score: {score})", fg=typer.colors.YELLOW)
                for r in raisons:
                    print(f"   -> {r}")
            else:
                typer.secho(f"Sain : {fichier.name} (Score: {score})", fg=typer.colors.GREEN)

        except Exception as e:
            print(f"Erreur globale sur {fichier.name} : {e}")


if __name__ == "__main__":
    app()