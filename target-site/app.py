import os
import sys

# Make sure submodules resolve correctly
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, redirect
from dotenv import load_dotenv
from db.init_db import init_db
from middleware.logger import setup_logging
from routes.auth import auth_bp
from routes.bank import bank_bp

load_dotenv(os.path.join(os.path.dirname(__file__), '../.env'))

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'fallback-secret-key')

# Init DB on startup
init_db()

# Attach logging middleware
setup_logging(app)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(bank_bp)

@app.route('/')
def index():
    return redirect('/login')

if __name__ == '__main__':
    port = int(os.getenv('TARGET_PORT', 3000))
    print(f'\n🏦  SecurBank running → http://localhost:{port}')
    print('⚠️   Intentionally vulnerable. Controlled environment only.\n')
    app.run(host='0.0.0.0', port=port, debug=False)
