# Projet 1 : Analyse des journaux d'un pare-feu

**Auteur :** OMAR LAYE SOW

Analyse d'une semaine de connexions enregistrées par un pare-feu (PC, serveurs, objets connectés) afin de détecter des comportements suspects.

## Lancer le projet

```bash
pip install -r requirements.txt
python analyse.py
```

Le fichier `data/logs_reseau.csv` doit être présent. Le script :

1. nettoie les données (doublons, protocole en majuscules, `bytes_sent` manquants remplacés par la médiane) ;
2. écrit les 5 résultats dans `resultats.json` ;
3. enregistre les figures dans `figures/` ;
4. génère `rapport.md` à partir des chiffres calculés.

## Contenu

| Fichier | Rôle |
|---|---|
| `analyse.py` | script principal |
| `data/logs_reseau.csv` | journaux du pare-feu |
| `resultats.json` | résultats générés |
| `figures/*.png` | graphiques générés |
| `rapport.md` | rapport d'analyse |
