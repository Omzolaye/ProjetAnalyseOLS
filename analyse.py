"""Analyse des journaux d'un pare-feu (projet 1 - Réseaux / Sécurité / IoT).

Usage : python analyse.py

Le script :
  1. lit data/logs_reseau.csv ;
  2. nettoie les données (doublons, casse du protocole, bytes_sent manquants) ;
  3. calcule les 5 résultats demandés et les écrit dans resultats.json ;
  4. enregistre des figures PNG dans figures/ ;
  5. génère rapport.md à partir des chiffres calculés.
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # pas besoin d'écran pour enregistrer les figures
import matplotlib.pyplot as plt
import pandas as pd

RACINE = Path(__file__).resolve().parent
CSV = RACINE / "data" / "logs_reseau.csv"
DOSSIER_FIG = RACINE / "figures"
JSON_SORTIE = RACINE / "resultats.json"
RAPPORT = RACINE / "rapport.md"

NOMS_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 1883: "MQTT", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt",
}


def nom_port(port):
    port = int(port)
    return f"{port} ({NOMS_PORTS[port]})" if port in NOMS_PORTS else str(port)


# --------------------------------------------------------------------------
# 1. Chargement et nettoyage
# --------------------------------------------------------------------------
def charger_et_nettoyer(chemin):
    brut = pd.read_csv(chemin)
    stats = {"lignes_brutes": len(brut)}

    # 1) doublons exacts
    df = brut.drop_duplicates().copy()
    stats["doublons_supprimes"] = len(brut) - len(df)

    # 2) protocole en MAJUSCULES (on retire aussi les espaces parasites)
    df["protocol"] = df["protocol"].astype("string").str.strip().str.upper()

    # 3) bytes_sent manquants -> médiane calculée après suppression des doublons
    df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors="coerce")
    stats["bytes_manquants"] = int(df["bytes_sent"].isna().sum())
    mediane = df["bytes_sent"].median()
    stats["mediane_bytes"] = float(mediane)
    df["bytes_sent"] = df["bytes_sent"].fillna(mediane)

    # Mise en forme (n'affecte pas les 5 résultats)
    df["action"] = df["action"].astype("string").str.strip().str.upper()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df.reset_index(drop=True), stats


# --------------------------------------------------------------------------
# 2. Résultats
# --------------------------------------------------------------------------
def calculer_resultats(df):
    return {
        "nb_lignes_apres_nettoyage": int(len(df)),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float((df["action"] == "DENY").mean() * 100), 2),
        "ip_scanner": str(df.groupby("src_ip")["dst_port"].nunique().idxmax()),
        "ip_exfiltration": str(df.groupby("src_ip")["bytes_sent"].sum().idxmax()),
    }


# --------------------------------------------------------------------------
# 3. Figures
# --------------------------------------------------------------------------
def enregistrer(fig, nom):
    fig.tight_layout()
    fig.savefig(DOSSIER_FIG / nom, dpi=130)
    plt.close(fig)


def faire_figures(df, res):
    DOSSIER_FIG.mkdir(exist_ok=True)

    # Fig 1 : top 10 des ports de destination
    top = df["dst_port"].value_counts().head(10)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar([nom_port(p) for p in top.index], top.values, color="#1f77b4")
    ax.set_title("Top 10 des ports de destination")
    ax.set_xlabel("Port de destination")
    ax.set_ylabel("Nombre de connexions")
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    enregistrer(fig, "01_top_ports.png")

    # Fig 2 : connexions par heure de la journée
    par_heure = df["timestamp"].dt.hour.value_counts().sort_index().reindex(range(24), fill_value=0)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(par_heure.index, par_heure.values, color="#2ca02c")
    ax.set_title("Connexions par heure de la journée")
    ax.set_xlabel("Heure (0-23)")
    ax.set_ylabel("Nombre de connexions")
    ax.set_xticks(range(0, 24, 2))
    enregistrer(fig, "02_connexions_par_heure.png")

    # Fig 3 : volume d'octets par type d'appareil
    vol = df.groupby("device_type")["bytes_sent"].sum().sort_values(ascending=False) / 1e6
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(vol.index, vol.values, color="#ff7f0e")
    ax.set_title("Volume d'octets envoyés par type d'appareil")
    ax.set_xlabel("Type d'appareil")
    ax.set_ylabel("Octets envoyés (Mo)")
    enregistrer(fig, "03_octets_par_appareil.png")

    # Fig 4 : répartition ALLOW / DENY
    rep = df["action"].value_counts()
    fig, ax = plt.subplots(figsize=(5.5, 5.5))
    couleurs = {"ALLOW": "#2ca02c", "DENY": "#d62728"}
    ax.pie(rep.values, labels=rep.index, autopct="%1.1f%%", startangle=90,
           colors=[couleurs.get(a, "grey") for a in rep.index])
    ax.set_title("Répartition ALLOW / DENY")
    enregistrer(fig, "04_allow_deny.png")

    # Fig 5 : top 10 des IP sources par nombre de ports distincts (scan)
    ports = df.groupby("src_ip")["dst_port"].nunique().sort_values(ascending=False).head(10)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(ports.index, ports.values,
           color=["#d62728" if ip == res["ip_scanner"] else "#7f7f7f" for ip in ports.index])
    ax.set_title("Ports distincts contactés par IP source (top 10)")
    ax.set_xlabel("IP source")
    ax.set_ylabel("Nombre de ports distincts")
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    enregistrer(fig, "05_ports_distincts_par_ip.png")

    # Fig 6 : top 10 des IP sources par volume d'octets (exfiltration)
    octets = df.groupby("src_ip")["bytes_sent"].sum().sort_values(ascending=False).head(10) / 1e6
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(octets.index, octets.values,
           color=["#d62728" if ip == res["ip_exfiltration"] else "#7f7f7f" for ip in octets.index])
    ax.set_title("Volume d'octets envoyés par IP source (top 10)")
    ax.set_xlabel("IP source")
    ax.set_ylabel("Octets envoyés (Mo)")
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    enregistrer(fig, "06_octets_par_ip.png")


# --------------------------------------------------------------------------
# 4. Rapport (rempli avec les chiffres calculés)
# --------------------------------------------------------------------------
def mo(x):
    return f"{x / 1e6:,.1f}".replace(",", " ")


def generer_rapport(df, res, stats):
    n = len(df)
    deb, fin = df["timestamp"].min(), df["timestamp"].max()
    nb_ip = df["src_ip"].nunique()

    # Preuves : scanner
    s = df[df["src_ip"] == res["ip_scanner"]]
    s_ports = s["dst_port"].nunique()
    s_deny = (s["action"] == "DENY").mean() * 100
    mediane_ports = df.groupby("src_ip")["dst_port"].nunique().median()
    s_dev = ", ".join(sorted(s["device_type"].dropna().unique()))

    # Preuves : exfiltration
    e = df[df["src_ip"] == res["ip_exfiltration"]]
    e_total = e["bytes_sent"].sum()
    total = df["bytes_sent"].sum()
    mediane_vol = df.groupby("src_ip")["bytes_sent"].sum().median()
    e_dev = ", ".join(sorted(e["device_type"].dropna().unique()))
    e_dst = e["dst_ip"].value_counts()
    e_port = e.groupby("dst_port")["bytes_sent"].sum().idxmax()
    e_allow = (e["action"] == "ALLOW").mean() * 100
    gros = e[e["bytes_sent"] > 1_000_000]
    nb_gros = len(gros)
    gros_mo = gros["bytes_sent"].sum() / 1e6
    gros_deb, gros_fin = gros["timestamp"].min(), gros["timestamp"].max()
    gros_nuit = int(((gros["timestamp"].dt.hour < 6) | (gros["timestamp"].dt.hour >= 22)).sum())
    mediane_conn = df["bytes_sent"].median()

    # scan : période, nombre de ports acceptés
    s_deb, s_fin = s["timestamp"].min(), s["timestamp"].max()
    s_allow = s[s["action"] == "ALLOW"]
    s_allow_ports = s_allow["dst_port"].nunique()

    # Telnet / IoT
    telnet = df[df["dst_port"] == 23]
    telnet_allow = int((telnet["action"] == "ALLOW").sum())
    iot = df["device_type"].astype(str).str.contains("IoT", case=False)
    mqtt_iot = int(((df["dst_port"] == 1883) & iot).sum())

    port_top = nom_port(res["top_port"])
    nb_top = int((df["dst_port"] == res["top_port"]).sum())

    tab_res = "\n".join([
        "| Indicateur | Valeur |", "|---|---|",
        f"| Lignes après nettoyage | {res['nb_lignes_apres_nettoyage']} |",
        f"| Port de destination le plus fréquent | {port_top} ({nb_top} connexions) |",
        f"| Taux de connexions bloquées (DENY) | {res['taux_deny_pct']} % |",
        f"| IP suspectée de scan | {res['ip_scanner']} |",
        f"| IP suspectée d'exfiltration | {res['ip_exfiltration']} |",
    ])

    return f"""# Rapport d'analyse des journaux du pare-feu

## Sommaire
1. Résumé
2. Nettoyage des données
3. Comportements suspects
4. Recommandations

## 1. Résumé

On a analysé {n} connexions ({stats['lignes_brutes']} lignes brutes avant nettoyage) enregistrées par le pare-feu du {deb:%d/%m/%Y} au {fin:%d/%m/%Y}, issues de {nb_ip} adresses sources. Le trafic est dominé par le port {port_top}, et {res['taux_deny_pct']} % des connexions ont été bloquées. Deux comportements anormaux ressortent : l'adresse {res['ip_scanner']} a contacté {s_ports} ports distincts, ce qui évoque un balayage de ports, et l'adresse {res['ip_exfiltration']} a envoyé {mo(e_total)} Mo, ce qui évoque une exfiltration de données. Enfin, on relève {len(telnet)} tentatives vers Telnet (port 23), protocole non chiffré à proscrire.

{tab_res}

## 2. Nettoyage des données

| Étape | Résultat |
|---|---|
| Doublons exacts supprimés | {stats['doublons_supprimes']} |
| Protocole mis en majuscules | valeurs : {', '.join(sorted(df['protocol'].dropna().unique()))} |
| `bytes_sent` manquants remplacés | {stats['bytes_manquants']} valeurs, par la médiane ({stats['mediane_bytes']:.0f} octets) |

## 3. Comportements suspects

### 3.1 Balayage de ports (scan) : {res['ip_scanner']}

- **Preuve :** cette adresse a contacté **{s_ports} ports distincts**, contre une médiane de {mediane_ports:.0f} pour l'ensemble des sources (figure `figures/05_ports_distincts_par_ip.png`).
- **Indices complémentaires :** {len(s)} connexions entre le {s_deb:%d/%m à %H:%M} et le {s_fin:%d/%m à %H:%M}, dont {s_deny:.1f} % bloquées par le pare-feu ; type d'appareil associé : {s_dev}. Attention : {s_allow_ports} ports ont tout de même été autorisés, ce qui signifie que des services ont répondu au scanner.
- **Interprétation :** une source qui teste un grand nombre de ports en peu de temps cherche les services exposés. C'est la phase de reconnaissance d'une attaque.

![Ports distincts par IP](figures/05_ports_distincts_par_ip.png)

### 3.2 Exfiltration de données : {res['ip_exfiltration']}

- **Preuve :** cette adresse a envoyé **{mo(e_total)} Mo**, soit {e_total / total * 100:.1f} % du volume total, contre une médiane de {mo(mediane_vol)} Mo par source (figure `figures/06_octets_par_ip.png`).
- **Indices complémentaires :** type d'appareil : {e_dev} ; {nb_gros} transferts de plus de 1 Mo ({gros_mo:.1f} Mo au total, contre une médiane de {mediane_conn:.0f} octets par connexion) entre le {gros_deb:%d/%m à %H:%M} et le {gros_fin:%d/%m à %H:%M}, dont {gros_nuit} la nuit (22 h à 6 h) ; destination principale : {e_dst.index[0]} ; port concentrant le volume : {nom_port(e_port)} ; {e_allow:.1f} % des connexions autorisées.
- **Interprétation :** un volume sortant très supérieur aux autres sources, vers une destination récurrente, correspond à un transfert massif de données, possiblement vers l'extérieur.

![Octets par IP](figures/06_octets_par_ip.png)

### 3.3 Autres observations

![Top ports](figures/01_top_ports.png)
![Connexions par heure](figures/02_connexions_par_heure.png)
![Octets par type d'appareil](figures/03_octets_par_appareil.png)
![Répartition ALLOW/DENY](figures/04_allow_deny.png)

- Telnet (port 23) : {len(telnet)} connexions, dont {telnet_allow} autorisées.
- MQTT (port 1883) : {mqtt_iot} connexions issues d'objets connectés.

## 4. Recommandations

1. **Bloquer et surveiller l'adresse {res['ip_scanner']}** : ajouter une règle DENY sur le pare-feu et activer une détection de balayage (seuil de ports distincts par minute).
2. **Enquêter sur {res['ip_exfiltration']}** : isoler la machine, identifier le contenu transféré, puis limiter le volume sortant (QoS / seuil d'alerte) et filtrer les destinations autorisées.
3. **Fermer Telnet (port 23)** : le remplacer par SSH (port 22) avec authentification par clé.
4. **Segmenter les objets IoT** (caméras, capteurs) dans un VLAN dédié, avec autorisation limitée aux seuls flux nécessaires (par exemple MQTT vers le broker).
5. **Journalisation et alertes** : centraliser les logs dans un SIEM et créer des alertes sur les pics de trafic hors horaires de bureau.
"""


# --------------------------------------------------------------------------
def main():
    df, stats = charger_et_nettoyer(CSV)
    res = calculer_resultats(df)
    JSON_SORTIE.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    faire_figures(df, res)
    RAPPORT.write_text(generer_rapport(df, res, stats), encoding="utf-8")
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
