import os
from app import create_app

app = create_app(os.environ.get("FLASK_ENV", "development"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = app.config.get("DEBUG", True)
    print(f"Starting AuthShield backend server on http://127.0.0.1:{port} (debug={debug})")
    app.run(host="127.0.0.1", port=port, debug=debug)
