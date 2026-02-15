

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scarica ARTICOLI.CSV da FTP, confronta con gli SKU pubblicati su Shopify
e genera un CSV contenente **solo i prodotti nuovi**.

Regole applicate:
- Esclude righe con ARDESART contenente '***'
- Esclude righe dove ARCODART non è numerico
- Normalizza ARCODART a 6 cifre con zeri a sinistra (es. 5522 -> 005522)
- Se ARCODART ha >6 cifre (tutte numeriche), scarta la riga e logga

USO (API Shopify):
  export_new_products_from_ftp.py \
    --ftp-host ftp.andreat257.sg-host.com \
    --ftp-user "admin@andreat257.sg-host.com" \
    --ftp-pass "1z$*j236|*db" \
    --ftp-path "/public_html/IMPORT_DATI_FULL_20230919_0940/ARTICOLI.CSV" \
    --sku-header ARCODART \
    --out "NUOVI_PRODOTTI.csv"

USO (senza API Shopify, con CSV SKU pubblicati):
  export_new_products_from_ftp.py ... --published-skus-csv "shopify_published_skus.csv"
"""

import csv
import io
import os
import sys
import time
import argparse
import logging
from typing import List, Dict, Set, Optional

try:
    from ftplib import FTP, FTP_TLS, error_perm
except Exception:
    FTP = None
    FTP_TLS = None
    error_perm = Exception

# --------- Config logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("new-products")

# ---------- Utils ----------
COMMON_SKU_HEADERS = [
    "SKU", "sku", "Codice", "CODICE", "codice",
    "CODART", "cod_articolo", "CodArt", "Cod_Art",
    "Codice Articolo", "Articolo", "RIF_CODICE", "RIFCODE",
]

def detect_delimiter(sample: str) -> str:
    sniffer = csv.Sniffer()
    try:
        dialect = sniffer.sniff(sample, delimiters=";,|\t,")
        return dialect.delimiter
    except Exception:
        return ";"

def detect_encoding(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            raw.decode(enc)
            return enc
        except Exception:
            continue
    return "latin-1"

def autodetect_sku_header(headers: List[str]) -> Optional[str]:
    norm = { (h or "").strip().lower(): (h or "") for h in headers }
    for candidate in [h.lower() for h in COMMON_SKU_HEADERS]:
        if candidate in norm:
            return norm[candidate]
    for h in headers:
        hn = (h or "").strip().lower()
        if "sku" == hn or hn.startswith("cod"):
            return h or ""
    return None

def ftp_connect(host: str, user: str, passwd: str, use_tls: bool = True):
    if use_tls and FTP_TLS is not None:
        ftp = FTP_TLS(host=host, timeout=60)
        ftp.login(user=user, passwd=passwd)
        try:
            ftp.prot_p()
        except Exception:
            pass
    else:
        ftp = FTP(host=host, timeout=60)
        ftp.login(user=user, passwd=passwd)
    return ftp

def ftp_download_file(host: str, user: str, passwd: str, path: str) -> bytes:
    log.info("Connessione FTP a %s ...", host)
    if "/" not in path:
        raise RuntimeError("FTP path non valido. Atteso percorso assoluto tipo /dir/file.csv")
    dirpath, filename = path.rsplit("/", 1)
    buf = io.BytesIO()
    ftp = None
    try:
        ftp = ftp_connect(host, user, passwd, use_tls=True)
    except Exception:
        ftp = ftp_connect(host, user, passwd, use_tls=False)
    try:
        if dirpath:
            log.info("Cambio directory: %s", dirpath)
            ftp.cwd(dirpath)
        log.info("Scarico file: %s", filename)
        ftp.retrbinary(f"RETR {filename}", buf.write)
    finally:
        try:
            ftp.quit()
        except Exception:
            pass
    raw = buf.getvalue()
    log.info("Scaricato %d bytes.", len(raw))
    return raw

# ---------- Normalizzazione SKU ----------
def normalize_sku_to_6_digits(value: str) -> Optional[str]:
    """
    Ritorna lo SKU normalizzato a 6 cifre (pad con zeri) se value è composto da sole cifre ed ha lunghezza 1..6.
    - Se value è vuoto o contiene caratteri non numerici -> None (da scartare)
    - Se value è numerico ma ha lunghezza >6 -> None (da scartare e loggare)
    """
    s = (value or "").strip()
    if not s or not s.isdigit():
        return None
    if len(s) > 6:
        return None
    return s.zfill(6)

def add_sku_variants_to_set(s: str, target: Set[str]) -> None:
    """
    Aggiunge allo set sia la forma originale sia (se applicabile) la forma normalizzata a 6 cifre.
    Questo permette di gestire negozi dove gli SKU su Shopify possono essere salvati con o senza zeri iniziali.
    """
    raw = (s or "").strip()
    if not raw:
        return
    target.add(raw)
    norm = normalize_sku_to_6_digits(raw)
    if norm:
        target.add(norm)

# ---------- Shopify ----------
import json
import urllib.request
import urllib.parse

def shopify_get_all_skus(store: str, token: str) -> Set[str]:
    """
    Scarica tutti gli SKU delle varianti prodotto da Shopify
    usando urllib (senza requests).
    """

    import json
    import urllib.request
    import urllib.parse

    api_version = "2023-10"
    base_url = f"https://{store}/admin/api/{api_version}/products.json"

    skus: Set[str] = set()
    next_url = base_url + "?limit=250&fields=id,variants"

    while next_url:
        req = urllib.request.Request(next_url)
        req.add_header("X-Shopify-Access-Token", token)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "Render-Cron/1.0")

        with urllib.request.urlopen(req, timeout=60) as response:
            data = json.loads(response.read().decode("utf-8"))
            headers = response.headers

        products = data.get("products", [])

        for product in products:
            for variant in product.get("variants", []):
                sku = (variant.get("sku") or "").strip()
                if sku:
                    skus.add(sku)

        # gestione paginazione Shopify
        link_header = headers.get("Link")
        next_url = None

        if link_header:
            parts = link_header.split(",")
            for part in parts:
                if 'rel="next"' in part:
                    start = part.find("<") + 1
                    end = part.find(">")
                    next_url = part[start:end]
                    break

    log.info("SKU Shopify rilevati: %d", len(skus))
    return skus
  
    """
    Scarica TUTTI gli SKU dalle varianti prodotto.
    Paginazione con header Link. Ritorna un set che include
    sia gli SKU così come sono su Shopify, sia la versione normalizzata a 6 cifre (se numerica <=6).
    """
    session = requests.Session()
    session.headers.update({
        "X-Shopify-Access-Token": token,
        "Accept": "application/json",
    })

    api_version = "2025-01"
    base = f"https://{store}/admin/api/{api_version}/products.json"
    params = {"limit": 250, "fields": "id,variants"}

    skus: Set[str] = set()
    url = base
    while True:
        resp = session.get(url, params=params, timeout=60)
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", "2"))
            log.warning("Rate limited. Retry after %ss", retry_after)
            time.sleep(retry_after)
            continue
        resp.raise_for_status()
        data = resp.json()
        products = data.get("products", [])
        for p in products:
            for v in p.get("variants", []):
                sku = (v.get("sku") or "").strip()
                if sku:
                    add_sku_variants_to_set(sku, skus)
        link = resp.headers.get("Link", "")
        next_url = None
        if link:
            parts = [p.strip() for p in link.split(",")]
            for part in parts:
                if 'rel="next"' in part:
                    start = part.find("<") + 1
                    end = part.find(">")
                    next_url = part[start:end]
                    break
        if next_url:
            url = next_url
            params = None
        else:
            break

    log.info("SKU Shopify rilevati (insieme normalizzato): %d", len(skus))
    return skus

def read_csv_rows(raw: bytes, forced_sku_header: Optional[str] = None):
    enc = detect_encoding(raw)
    text = raw.decode(enc, errors="replace")
    sample = text[:10000]
    delimiter = detect_delimiter(sample)
    log.info("Encoding rilevato: %s | Delimitatore: %r", enc, delimiter)

    buf = io.StringIO(text)
    reader = csv.DictReader(buf, delimiter=delimiter)
    headers = reader.fieldnames or []
    if not headers:
        raise RuntimeError("Intestazioni CSV non trovate.")

    if forced_sku_header:
        if forced_sku_header not in headers:
            raise RuntimeError(
                f"Colonna SKU forzata '{forced_sku_header}' non trovata. Intestazioni disponibili: {headers}"
            )
        sku_header = forced_sku_header
    else:
        sku_header = autodetect_sku_header(headers)

    if not sku_header:
        raise RuntimeError(
            f"Colonna SKU non rilevata. Intestazioni disponibili: {headers}"
        )

    rows = list(reader)
    return rows, headers, delimiter, sku_header

def load_published_skus_from_csv(path: str) -> Set[str]:
    skus: Set[str] = set()
    with open(path, "r", encoding="utf-8") as f:
        sample = f.read(10000)
        delim = detect_delimiter(sample)
        f.seek(0)
        reader = csv.DictReader(f, delimiter=delim)
        headers = reader.fieldnames or []
        sku_h = autodetect_sku_header(headers)
        if not sku_h:
            raise RuntimeError(
                f"Impossibile rilevare colonna SKU nel CSV pubblicato. Headers: {headers}"
            )
        for r in reader:
            s = (r.get(sku_h) or "").strip()
            if s:
                add_sku_variants_to_set(s, skus)
    log.info("SKU pubblicati (da CSV, insieme normalizzato): %d", len(skus))
    return skus

def write_csv(path: str, headers: List[str], delimiter: str, rows: List[Dict]):
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers, delimiter=delimiter, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    log.info("Scritto file: %s (righe: %d)", path, len(rows))

def main():
    ap = argparse.ArgumentParser(description="Genera CSV con nuovi prodotti (non presenti su Shopify).")
    ap.add_argument("--ftp-host", required=True)
    ap.add_argument("--ftp-user", required=True)
    ap.add_argument("--ftp-pass", required=True)
    ap.add_argument("--ftp-path", required=True, help="Percorso assoluto del file sul server FTP (es. /public_html/.../ARTICOLI.CSV)")
    ap.add_argument("--out", default="NUOVI_PRODOTTI.csv", help="Percorso output CSV filtrato")
    ap.add_argument("--published-skus-csv", default=None, help="(Opzionale) CSV locale con SKU già pubblicati su Shopify; se presente, NON usa l'API Shopify.")
    ap.add_argument("--sku-header", default=None, help="Nome esatto della colonna SKU nel CSV (es. ARCODART)")
    args = ap.parse_args()

    # 1) Scarica CSV da FTP
    raw = ftp_download_file(args.ftp_host, args.ftp_user, args.ftp_pass, args.ftp_path)

    # 2) Parsing CSV (con eventuale override dell'header SKU)
    rows, headers, delimiter, sku_header = read_csv_rows(raw, forced_sku_header=args.sku_header)
    log.info("Righe totali nel CSV di origine: %d", len(rows))
    log.info("Colonna SKU usata: %s", sku_header)

    # Colonna per filtri extra
    ardesart_h = "ARDESART" if "ARDESART" in headers else None

    # 3) Recupera SKU pubblicati
    if args.published_skus_csv:
        published_skus = load_published_skus_from_csv(args.published_skus_csv)
    else:
        store = os.getenv("SHOPIFY_STORE", "").strip()
        token = os.getenv("SHOPIFY_TOKEN", "").strip()
        log.info("STORE usato: %s", store)
        log.info("TOKEN primi 8 caratteri: %s", token[:8] if token else "VUOTO")
        if not store or not token:
            log.error("Mancano variabili d'ambiente SHOPIFY_STORE / SHOPIFY_TOKEN oppure --published-skus-csv. Interrompo.")
            sys.exit(2)
        published_skus = shopify_get_all_skus(store, token)

    # 4) Filtra righe con regole + confronto con Shopify (insieme normalizzato)
    new_rows: List[Dict] = []
    seen_in_input: Set[str] = set()

    empty_sku_rows = 0
    skipped_stars_ardesart = 0
    skipped_sku_not_numeric = 0
    skipped_sku_too_long = 0

    for r in rows:
        # Regola 1: escludi se ARDESART contiene '***'
        if ardesart_h:
            val = (r.get(ardesart_h) or "").strip()
            if "***" in val:
                skipped_stars_ardesart += 1
                continue

        raw_sku = (r.get(sku_header) or "").strip()

        if not raw_sku:
            empty_sku_rows += 1
            continue

        # Normalizza a 6 cifre; se non numerico o troppo lungo -> scarta
        norm = normalize_sku_to_6_digits(raw_sku)
        if norm is None:
            if raw_sku.isdigit() and len(raw_sku) > 6:
                skipped_sku_too_long += 1
            else:
                skipped_sku_not_numeric += 1
            continue

        # Evita duplicati nell'input (dopo normalizzazione)
        if norm in seen_in_input:
            continue
        seen_in_input.add(norm)

        # Aggiorna la riga con lo SKU normalizzato (così l'output è già corretto a 6 cifre)
        r[sku_header] = norm

        # Confronto con Shopify: published_skus contiene sia raw sia padded
        if norm not in published_skus:
            new_rows.append(r)

    log.info("Righe senza SKU: %d", empty_sku_rows)
    log.info("Righe escluse per ARDESART contenente '***': %d", skipped_stars_ardesart)
    log.info("Righe escluse per SKU non numerico/invalidi: %d", skipped_sku_not_numeric)
    log.info("Righe escluse per SKU > 6 cifre: %d", skipped_sku_too_long)
    log.info("Nuovi prodotti rilevati: %d", len(new_rows))

    # 5) Scrivi output mantenendo le stesse colonne dell'input (con SKU a 6 cifre)
    write_csv(args.out, headers, delimiter, new_rows)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.warning("Interrotto dall'utente.")
        sys.exit(130)
    except Exception as e:
        log.exception("Errore: %s", e)
        sys.exit(1)
