import http.server
import ssl
import os
from pathlib import Path

PORT = 8443
BASE_DIR = Path(__file__).resolve().parent
FILES_DIR = BASE_DIR / "files"
CERT_FILE = BASE_DIR / "certs" / "server.crt"
KEY_FILE  = BASE_DIR / "certs" / "server.key"

class Handler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        path = path.split("?", 1)[0].split("#", 1)[0]
        rel = path.lstrip("/")
        full = (FILES_DIR / rel).resolve()
        if not str(full).startswith(str(FILES_DIR.resolve())):
            return str(FILES_DIR / "manifest.json")
        return str(full)

    def do_GET(self):
        try:
            if self.path.startswith("/manifest.json") or self.path.startswith("/firmware.bin"):
                return super().do_GET()
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found. Use /manifest.json or /firmware.bin\n")
        except (ConnectionResetError, BrokenPipeError):
            # Client aborted download (common during OTA failures). Ignore.
            return

def main():
    os.chdir(FILES_DIR)
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"HTTPS OTA server running on :{PORT}")
    httpd.serve_forever()

if __name__ == "__main__":
    main()
