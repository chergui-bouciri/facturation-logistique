#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
سيرفر مركزي - Serveur central de facturation logistique (emballages)
- كايخدم فالشبكة المحلية ديال المقاولة (بلا انترنيت خارجي)
- قاعدة بيانات وحدة مشتركة بين جميع البوسطات
- غير الأدمين (بكلمة السر) يقدر يزيد/يبدل الشركات والأكواد
- بقية البوسطات يقدرو يصاوبو الفواتير غير
"""

import os
import io
import sqlite3
import secrets
from datetime import date, datetime
from functools import wraps

from flask import Flask, request, jsonify, session, send_file, render_template

from werkzeug.security import generate_password_hash, check_password_hash

try:
    from emballages_data import EMBALLAGES_INITIALES
except ImportError:
    EMBALLAGES_INITIALES = []

try:
    from clients_data import CLIENTS_INITIAUX
except ImportError:
    CLIENTS_INITIAUX = []

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "facturation_reseau.db")
SECRET_KEY_PATH = os.path.join(BASE_DIR, ".secret_key")

DEFAULT_ADMIN_PASSWORD = "admin123"  # !! khassek tbadalha men b3d men l'interface (Espace Admin > Changer mot de passe)

app = Flask(__name__)

# clé de session persistante (pour ne pas déconnecter tout le monde à chaque redémarrage)
if os.path.exists(SECRET_KEY_PATH):
    with open(SECRET_KEY_PATH, "r") as f:
        app.secret_key = f.read().strip()
else:
    key = secrets.token_hex(32)
    with open(SECRET_KEY_PATH, "w") as f:
        f.write(key)
    app.secret_key = key


# =========================================================
#                      BASE DE DONNÉES
# =========================================================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS emballages (
            code_emballage TEXT PRIMARY KEY,
            code TEXT,
            nature TEXT,
            prix REAL DEFAULT 0,
            poids REAL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT UNIQUE NOT NULL,
            adresse TEXT, ice TEXT, nif TEXT, rib TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS admin_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS factures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            numero TEXT, date_facture TEXT, client_id INTEGER,
            numero_bl TEXT, incoterm TEXT,
            FOREIGN KEY (client_id) REFERENCES clients(id)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS lignes_facture (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            facture_id INTEGER NOT NULL,
            code_emballage TEXT, designation TEXT,
            quantite REAL, prix_unitaire REAL, poids_unitaire REAL,
            FOREIGN KEY (facture_id) REFERENCES factures(id) ON DELETE CASCADE
        )
    """)

    cur.execute("SELECT COUNT(*) FROM emballages")
    if cur.fetchone()[0] == 0 and EMBALLAGES_INITIALES:
        cur.executemany(
            "INSERT OR IGNORE INTO emballages (code, code_emballage, nature, prix, poids) VALUES (?,?,?,?,?)",
            EMBALLAGES_INITIALES,
        )

    cur.execute("SELECT COUNT(*) FROM clients")
    if cur.fetchone()[0] == 0 and CLIENTS_INITIAUX:
        cur.executemany("INSERT OR IGNORE INTO clients (nom) VALUES (?)", [(c,) for c in CLIENTS_INITIAUX])

    cur.execute("SELECT COUNT(*) FROM admin_config")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO admin_config (id, password_hash) VALUES (1, ?)",
                    (generate_password_hash(DEFAULT_ADMIN_PASSWORD),))

    conn.commit()
    conn.close()


# =========================================================
#                 AUTHENTIFICATION ADMIN
# =========================================================
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"error": "Accès refusé - Connexion admin requise / خاصك تدخل كأدمين"}), 403
        return f(*args, **kwargs)
    return wrapper


@app.route("/api/session")
def api_session():
    return jsonify({"is_admin": bool(session.get("is_admin"))})


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True)
    password = (data or {}).get("password", "")
    conn = get_db()
    row = conn.execute("SELECT password_hash FROM admin_config WHERE id=1").fetchone()
    conn.close()
    if row and check_password_hash(row["password_hash"], password):
        session["is_admin"] = True
        session.permanent = True
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "كلمة السر غالطة / Mot de passe incorrect"}), 401


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.pop("is_admin", None)
    return jsonify({"ok": True})


@app.route("/api/change_password", methods=["POST"])
@admin_required
def api_change_password():
    data = request.get_json(force=True)
    new_password = (data or {}).get("new_password", "").strip()
    if len(new_password) < 4:
        return jsonify({"ok": False, "error": "كلمة السر خاصها 4 حروف/أرقام على الأقل"}), 400
    conn = get_db()
    conn.execute("UPDATE admin_config SET password_hash=? WHERE id=1", (generate_password_hash(new_password),))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# =========================================================
#                       EMBALLAGES
# =========================================================
@app.route("/api/emballages")
def api_emballages_list():
    conn = get_db()
    rows = conn.execute("SELECT * FROM emballages ORDER BY code_emballage").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/emballages", methods=["POST"])
@admin_required
def api_emballages_upsert():
    data = request.get_json(force=True)
    code_emb = (data.get("code_emballage") or "").strip().upper()
    if not code_emb:
        return jsonify({"ok": False, "error": "Code Emballage واجب"}), 400
    try:
        prix = float(data.get("prix", 0))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "الثمن خاصو يكون رقم"}), 400
    poids_raw = data.get("poids", None)
    poids = None
    if poids_raw not in (None, ""):
        try:
            poids = float(poids_raw)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "الوزن خاصو يكون رقم"}), 400

    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO emballages (code_emballage, code, nature, prix, poids) VALUES (?,?,?,?,?)",
        (code_emb, data.get("code", ""), data.get("nature", ""), prix, poids),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/emballages/<code_emballage>", methods=["DELETE"])
@admin_required
def api_emballages_delete(code_emballage):
    conn = get_db()
    conn.execute("DELETE FROM emballages WHERE code_emballage=?", (code_emballage,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# =========================================================
#                         CLIENTS
# =========================================================
@app.route("/api/clients")
def api_clients_list():
    conn = get_db()
    rows = conn.execute("SELECT * FROM clients ORDER BY nom").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/clients", methods=["POST"])
@admin_required
def api_clients_upsert():
    data = request.get_json(force=True)
    nom = (data.get("nom") or "").strip()
    if not nom:
        return jsonify({"ok": False, "error": "اسم الشركة واجب"}), 400

    conn = get_db()
    existing = conn.execute("SELECT id FROM clients WHERE nom=?", (nom,)).fetchone()
    if existing:
        conn.execute(
            "UPDATE clients SET adresse=?, ice=?, nif=?, rib=? WHERE id=?",
            (data.get("adresse", ""), data.get("ice", ""), data.get("nif", ""), data.get("rib", ""), existing["id"]),
        )
    else:
        conn.execute(
            "INSERT INTO clients (nom, adresse, ice, nif, rib) VALUES (?,?,?,?,?)",
            (nom, data.get("adresse", ""), data.get("ice", ""), data.get("nif", ""), data.get("rib", "")),
        )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/clients/<int:client_id>", methods=["DELETE"])
@admin_required
def api_clients_delete(client_id):
    conn = get_db()
    conn.execute("DELETE FROM clients WHERE id=?", (client_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# =========================================================
#                        FACTURES
# =========================================================
@app.route("/api/factures", methods=["POST"])
def api_factures_create():
    data = request.get_json(force=True)
    client_id = data.get("client_id")
    lignes_in = data.get("lignes", [])
    if not client_id or not lignes_in:
        return jsonify({"ok": False, "error": "الشركة والسطور واجبين"}), 400

    conn = get_db()
    client = conn.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    if not client:
        conn.close()
        return jsonify({"ok": False, "error": "الشركة ماكايناش"}), 400

    numero = data.get("numero") or f"AUTO-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    date_facture = data.get("date") or date.today().strftime("%d/%m/%Y")

    cur = conn.cursor()
    cur.execute(
        "INSERT INTO factures (numero, date_facture, client_id, numero_bl, incoterm) VALUES (?,?,?,?,?)",
        (numero, date_facture, client_id, data.get("numero_bl", ""), data.get("incoterm", "FCA")),
    )
    facture_id = cur.lastrowid

    for l in lignes_in:
        code_emb = l.get("code_emballage")
        qte = float(l.get("quantite", 0))
        emb = conn.execute("SELECT * FROM emballages WHERE code_emballage=?", (code_emb,)).fetchone()
        if not emb:
            continue
        # le prix/poids/désignation viennent TOUJOURS du serveur (jamais du navigateur) pour l'intégrité
        cur.execute(
            "INSERT INTO lignes_facture (facture_id, code_emballage, designation, quantite, prix_unitaire, poids_unitaire) "
            "VALUES (?,?,?,?,?,?)",
            (facture_id, code_emb, emb["nature"], qte, emb["prix"], emb["poids"]),
        )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "facture_id": facture_id, "numero": numero})


@app.route("/api/factures")
def api_factures_list():
    conn = get_db()
    rows = conn.execute("""
        SELECT f.id, f.numero, f.date_facture, c.nom as client, f.numero_bl
        FROM factures f LEFT JOIN clients c ON f.client_id = c.id
        ORDER BY f.id DESC LIMIT 300
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/factures/<int:facture_id>/pdf")
def api_facture_pdf(facture_id):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import simpleSplit

    conn = get_db()
    facture = conn.execute("SELECT * FROM factures WHERE id=?", (facture_id,)).fetchone()
    if not facture:
        conn.close()
        return jsonify({"error": "introuvable"}), 404
    client = conn.execute("SELECT * FROM clients WHERE id=?", (facture["client_id"],)).fetchone()
    lignes = conn.execute("SELECT * FROM lignes_facture WHERE facture_id=?", (facture_id,)).fetchall()
    conn.close()

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    y = height - 20 * mm

    c.setFont("Helvetica-Bold", 13)
    c.drawString(20 * mm, y, "RENAULT TANGER EXPLOITATION SAS")
    c.setFont("Helvetica", 8)
    y -= 5 * mm
    for txt in [
        "Société Anonyme Simplifiée au capital de 30.000.000,00 EUR",
        "Zone Franche de Melloussa, Commune de Melloussa, Tanger, Maroc",
        "Tél : +212 (0) 539 37 13 28 - RC : 42591 - Patente : 582 86 305",
        "Banque : ATTIJARIWAFA BANK - RIB : 605 640 000000 200 808 2470 01",
    ]:
        c.drawString(20 * mm, y, txt)
        y -= 4 * mm

    c.setFont("Helvetica-Bold", 14)
    c.drawRightString(width - 20 * mm, height - 20 * mm, "Facture Proforma")
    c.setFont("Helvetica", 9)
    c.drawRightString(width - 20 * mm, height - 26 * mm, f"N° document: {facture['numero']}")
    c.drawRightString(width - 20 * mm, height - 31 * mm, f"Date: {facture['date_facture']}")

    y -= 6 * mm
    c.line(20 * mm, y, width - 20 * mm, y)
    y -= 8 * mm

    c.setFont("Helvetica-Bold", 9)
    c.drawString(20 * mm, y, "Destinataire:")
    c.setFont("Helvetica-Bold", 11)
    c.drawString(45 * mm, y, client["nom"] if client else "")
    y -= 5 * mm
    c.setFont("Helvetica", 8)
    if client and client["adresse"]:
        for ligne in simpleSplit(client["adresse"], "Helvetica", 8, 100 * mm):
            c.drawString(45 * mm, y, ligne)
            y -= 4 * mm
    if client and client["ice"]:
        c.drawString(45 * mm, y, f"ICE: {client['ice']}")
        y -= 4 * mm
    if client and client["nif"]:
        c.drawString(45 * mm, y, f"NIF: {client['nif']}")
        y -= 4 * mm
    if client and client["rib"]:
        c.drawString(45 * mm, y, f"RIB: {client['rib']}")
        y -= 4 * mm

    y -= 4 * mm
    total_qte_hdr = sum((l["quantite"] or 0) for l in lignes)
    c.setFont("Helvetica", 9)
    c.drawString(20 * mm, y, f"Numéro de BL: {facture['numero_bl'] or ''}")
    c.drawString(120 * mm, y, f"Nombre de contenants: {total_qte_hdr:.0f}")
    y -= 6 * mm
    c.drawString(20 * mm, y, f"Incoterm: {facture['incoterm'] or ''}")
    poids_total_general = sum((l["quantite"] or 0) * (l["poids_unitaire"] or 0) for l in lignes)
    c.drawString(120 * mm, y, f"Poids total (kg): {poids_total_general:.2f}")
    y -= 10 * mm

    headers = ["Article", "Désignation", "Quantité", "Prix Unitaire", "Montant H.T", "Poids unitaire", "Poids total"]
    col_widths = [22, 45, 20, 25, 25, 25, 25]
    x_start = 20 * mm
    row_h = 6 * mm

    def draw_row(values, y_pos, bold=False, fill=None):
        x = x_start
        if fill:
            c.setFillColor(fill)
            c.rect(x_start, y_pos - row_h + 1.5 * mm, sum(col_widths) * mm, row_h, fill=1, stroke=0)
            c.setFillColor(colors.black)
        c.setFont("Helvetica-Bold" if bold else "Helvetica", 8)
        for val, w in zip(values, col_widths):
            c.drawString(x + 1 * mm, y_pos - row_h + 2 * mm, str(val))
            x += w * mm
        c.setLineWidth(0.3)
        c.line(x_start, y_pos - row_h, x_start + sum(col_widths) * mm, y_pos - row_h)

    draw_row(headers, y, bold=True, fill=colors.Color(0.85, 0.85, 0.85))
    y -= row_h

    total_qte = total_montant = total_poids = 0
    for l in lignes:
        qte = l["quantite"] or 0
        prix_u = l["prix_unitaire"] or 0
        poids_u = l["poids_unitaire"] or 0
        montant = qte * prix_u
        poids_tot = qte * poids_u
        total_qte += qte
        total_montant += montant
        total_poids += poids_tot

        if y < 30 * mm:
            c.showPage()
            y = height - 20 * mm

        draw_row([
            l["code_emballage"], (l["designation"] or "")[:28], f"{qte:.0f}",
            f"{prix_u:.2f}", f"{montant:.2f}",
            "N/A" if l["poids_unitaire"] is None else f"{poids_u:.2f}",
            f"{poids_tot:.2f}",
        ], y)
        y -= row_h

    y -= 3 * mm
    c.setFont("Helvetica-Bold", 9)
    c.drawString(x_start, y, f"Total quantité: {total_qte:.0f}")
    c.drawString(x_start + 70 * mm, y, f"Total Montant H.T: {total_montant:.2f}")
    c.drawString(x_start + 140 * mm, y, f"Total Poids: {total_poids:.2f} kg")

    c.setFont("Helvetica-Oblique", 7)
    c.drawString(20 * mm, 15 * mm, "Document généré automatiquement - Facture Proforma non contractuelle.")
    c.save()
    buf.seek(0)

    return send_file(buf, mimetype="application/pdf", as_attachment=False,
                      download_name=f"Facture_{facture['numero']}.pdf".replace("/", "-"))


# =========================================================
#                       PAGE PRINCIPALE
# =========================================================
@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    init_db()
    import socket
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "127.0.0.1"
    print("=" * 60)
    print("  السيرفر خدام / Serveur démarré")
    print(f"  فهاد الكمبيوتر: http://127.0.0.1:5000")
    print(f"  من كمبيوترات أخرى فنفس الشبكة: http://{local_ip}:5000")
    print(f"  كلمة سر الأدمين ديال البداية: {DEFAULT_ADMIN_PASSWORD}  (بدلها من Espace Admin)")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
