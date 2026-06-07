import os
from flask import Flask, render_template, request, jsonify
import random

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = Flask(__name__, template_folder=os.path.join(base_dir, '../templates'))

# ==========================================
# LOGIKA MATEMATIKA ELGAMAL (100% Original)
# ==========================================

def gcd(a, b):
    """Mencari FPB untuk syarat k."""
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    """Mencari invers modular (Extended Euclidean Algorithm) - Kilat!"""
    m0, y, x = m, 0, 1
    if m == 1: return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    return x + m0 if x < 0 else x

def generate_k(p):
    """Generate k acak yang relatif prima dengan p-1."""
    while True:
        k = random.randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            return k

# Parameter Primer
p = 18446744073709551557
g = 13

# ==========================================
# ROUTES
# ==========================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate-keys', methods=['GET'])
def generate_keys():
    """Generate pasangan kunci publik dan privat baru."""
    x = random.randint(2, p - 2)      # Private Key
    y = pow(g, x, p)                   # Public Key
    return jsonify({
        'p': str(p),
        'g': g,
        'x': str(x),
        'y': str(y)
    })


@app.route('/encrypt-number', methods=['POST'])
def encrypt_number():
    """Enkripsi & Dekripsi pesan berupa angka."""
    data = request.get_json()
    try:
        m = int(data['message'])
        x = int(data['private_key'])
        y = int(data['public_key_y'])
    except (KeyError, ValueError) as e:
        return jsonify({'error': f'Input tidak valid: {str(e)}'}), 400

    if m >= p:
        return jsonify({'error': f'Angka terlalu besar, maksimal {p - 1}'}), 400

    # Enkripsi
    k  = generate_k(p)
    c1 = pow(g, k, p)
    s  = pow(y, k, p)
    c2 = (m * s) % p

    # Dekripsi
    s_dec = pow(c1, x, p)
    s_inv = mod_inverse(s_dec, p)
    m_dec = (c2 * s_inv) % p

    return jsonify({
        'k':       str(k),
        'c1':      str(c1),
        'c2':      str(c2),
        'decrypted': str(m_dec)
    })


@app.route('/encrypt-text', methods=['POST'])
def encrypt_text():
    """Enkripsi & Dekripsi pesan berupa teks (per karakter)."""
    data = request.get_json()
    try:
        text    = data['message']
        x       = int(data['private_key'])
        y       = int(data['public_key_y'])
    except (KeyError, ValueError) as e:
        return jsonify({'error': f'Input tidak valid: {str(e)}'}), 400

    if not text:
        return jsonify({'error': 'Pesan tidak boleh kosong'}), 400

    ciphertexts  = []
    decrypted    = []

    for char in text:
        m_char = ord(char)
        k      = generate_k(p)
        c1     = pow(g, k, p)
        s      = pow(y, k, p)
        c2     = (m_char * s) % p
        ciphertexts.append({'c1': str(c1), 'c2': str(c2)})

        # Dekripsi langsung
        s_dec = pow(c1, x, p)
        s_inv = mod_inverse(s_dec, p)
        m_dec = (c2 * s_inv) % p
        decrypted.append(chr(m_dec))

    return jsonify({
        'blocks':    ciphertexts,
        'decrypted': ''.join(decrypted)
    })


app = app
