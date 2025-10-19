# Shopify New Product Exporter

Script Python per scaricare `ARTICOLI.CSV` da FTP, confrontare gli SKU con quelli già pubblicati su Shopify e generare un CSV con **solo i nuovi prodotti**.

## 🔧 Requisiti

- Python 3.10+
- Dipendenze: `pip install -r requirements.txt`
- Accesso FTP e API Shopify Admin

## 🚀 Esecuzione
```bash
python3 export_new_products_from_ftp.py \
  --ftp-host ftp.andreat257.sg-host.com \
  --ftp-user "admin@andreat257.sg-host.com" \
  --ftp-pass "33;k;gk|k^y2" \
  --ftp-path "/public_html/IMPORT_DATI_FULL_20230919_0940/ARTICOLI.CSV" \
  --out "NUOVI_PRODOTTI.csv"
