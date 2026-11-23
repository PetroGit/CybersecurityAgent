from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            payload = {'status': 'ok'}
        elif self.path == '/api/v1/products':
            payload = {'products': [{'id': 'demo-1', 'name': 'Sample product'}]}
        elif self.path == '/':
            data = b'<!doctype html><html><head><title>CybersecurityAgent Demo</title></head><body><h1>CybersecurityAgent Local Test</h1><a href="/api/v1/products">Products API</a></body></html>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        else:
            self.send_error(404)
            return
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
