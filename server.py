#!/usr/bin/env python3
import http.server
import socketserver
import os
import shutil
import webbrowser
from urllib.parse import unquote, quote
import mimetypes
import zipfile
import io
from datetime import datetime

PORT = 8000
BASE_DIR = os.getcwd()
SHOW_HIDDEN = False

def format_size(bytes):
    if bytes == 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024:
            return f"{bytes:.1f} {unit}"
        bytes /= 1024
    return f"{bytes:.1f} PB"

def generate_directory_listing(path):
    global SHOW_HIDDEN
    rel_path = os.path.relpath(path, BASE_DIR)
    if rel_path == '.':
        rel_path = ''

    try:
        items = os.listdir(path)
    except PermissionError:
        return generate_error("Access Denied")

    dirs = []
    files = []

    for item in sorted(items, key=str.lower):
        if not SHOW_HIDDEN and item.startswith('.'):
            continue
        full_path = os.path.join(path, item)
        try:
            is_dir = os.path.isdir(full_path)
            stat = os.stat(full_path)
            size = stat.st_size if not is_dir else 0
            mtime = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')

            if is_dir:
                dirs.append((item, size, mtime, True))
            else:
                files.append((item, size, mtime, False))
        except:
            continue

    items = dirs + files

    breadcrumb = ''
    if rel_path:
        parts = rel_path.split(os.sep)
        crumbs = ['<a href="/">Home</a>']
        current = ''
        for part in parts:
            current = os.path.join(current, part) if current else part
            crumbs.append(f'<a href="/browse/{quote(current)}">{part}</a>')
        breadcrumb = ' / '.join(crumbs)
    else:
        breadcrumb = 'Home'

    rows = ''
    if rel_path:
        parent = os.path.dirname(rel_path)
        parent_url = f'/browse/{quote(parent)}' if parent else '/'
        rows += f'<tr><td colspan="4"><a href="{parent_url}" class="parent-link">..</a></td></tr>'

    for name, size, mtime, is_dir in items:
        item_path = os.path.join(rel_path, name) if rel_path else name

        if is_dir:
            url = f'/browse/{quote(item_path)}'
            rows += f'<tr><td class="icon">📁</td><td class="file-name"><a href="{url}">{name}</a></td><td class="file-size">—</td><td class="file-actions">{mtime}</td></tr>'
        else:
            view_url = f'/view/{quote(item_path)}'
            download_url = f'/download/{quote(item_path)}'
            size_str = format_size(size)
            rows += f'<tr><td class="icon">📄</td><td class="file-name"><a href="{view_url}">{name}</a></td><td class="file-size">{size_str}</td><td class="file-actions"><div class="action-row"><span class="date">{mtime}</span><a href="{download_url}" class="btn-dl">Download</a></div></td></tr>'

    download_all = f'<a href="/download-all/{quote(rel_path)}" class="btn-zip">Download ZIP</a>' if items else ''

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{rel_path or 'Root'}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh;padding:24px}}
.header{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px 24px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,0.12)}}
.breadcrumb{{font-size:15px;margin-bottom:16px;color:#8b949e}}
.breadcrumb a{{color:#58a6ff;text-decoration:none}}
.breadcrumb a:hover{{text-decoration:underline}}
.btn-zip{{display:inline-block;padding:8px 16px;background:#238636;color:#fff;text-decoration:none;border-radius:6px;font-size:14px;font-weight:500}}
.btn-zip:hover{{background:#2ea043}}
.container{{max-width:1400px;margin:0 auto}}
.table-box{{background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.12)}}
table{{width:100%;border-collapse:collapse}}
th{{background:#0d1117;color:#8b949e;text-align:left;padding:12px 20px;font-weight:600;font-size:13px;border-bottom:1px solid #30363d}}
td{{padding:12px 20px;border-bottom:1px solid #21262d;vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
tr:hover{{background:rgba(110,118,129,0.04)}}
.icon{{width:40px;font-size:20px;text-align:center}}
.file-name{{min-width:250px;max-width:700px;word-break:break-word}}
.file-name a{{color:#58a6ff;text-decoration:none}}
.file-name a:hover{{text-decoration:underline}}
.file-size{{width:120px;text-align:right;color:#8b949e;white-space:nowrap}}
.file-actions{{min-width:200px;text-align:right}}
.action-row{{display:flex;align-items:center;justify-content:flex-end;gap:12px;flex-wrap:nowrap}}
.date{{color:#8b949e;font-size:13px;white-space:nowrap}}
.btn-dl{{display:inline-block;padding:5px 12px;background:rgba(110,118,129,0.15);color:#c9d1d9;text-decoration:none;border-radius:4px;font-size:12px;transition:all 0.2s;white-space:nowrap;flex-shrink:0}}
.btn-dl:hover{{background:#238636;color:#fff}}
.parent-link{{color:#58a6ff;font-weight:600;text-decoration:none}}
.parent-link:hover{{text-decoration:underline}}
@media(max-width:1024px){{
body{{padding:16px}}
.header{{padding:16px 20px}}
th,td{{padding:10px 16px}}
}}
@media(max-width:768px){{
body{{padding:12px}}
.header{{padding:14px 16px}}
.breadcrumb{{font-size:14px}}
table{{font-size:14px}}
th,td{{padding:8px 12px}}
.icon{{width:32px;font-size:18px}}
.file-name{{min-width:150px;max-width:350px}}
.file-size{{width:80px;font-size:12px}}
.file-actions{{min-width:auto}}
.action-row{{gap:8px}}
.date{{font-size:12px}}
.btn-dl{{padding:4px 10px;font-size:11px}}
}}
@media(max-width:640px){{
body{{padding:10px}}
.header{{padding:12px 14px}}
th,td{{padding:6px 10px}}
.icon{{display:none}}
.file-name{{min-width:120px;max-width:250px;font-size:13px}}
.file-size{{width:65px;font-size:11px}}
.file-actions{{min-width:auto}}
.action-row{{flex-direction:column;align-items:flex-end;gap:4px}}
.date{{font-size:10px}}
.btn-dl{{padding:4px 8px;font-size:10px}}
}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<div class="breadcrumb">{breadcrumb}</div>
{download_all}
</div>
<div class="table-box">
<table>
<thead>
<tr>
<th class="icon"></th>
<th class="file-name">File Name</th>
<th class="file-size">File Size</th>
<th class="file-actions">Last Modified</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</div>
</div>
</body>
</html>"""

def generate_error(message):
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Error</title>
<style>body{{font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:3rem;text-align:center}}a{{color:#58a6ff}}</style>
</head><body><h2>Error: {message}</h2><br><a href="/">Go back</a></body></html>"""

def generate_file_view(filepath, content):
    filename = os.path.basename(filepath)
    ext = os.path.splitext(filename)[1].lower()

    text_exts = ['.txt','.py','.js','.html','.css','.json','.xml','.md','.yml','.yaml','.sh','.bash','.conf','.cfg','.ini','.log','.sql','.csv','.env','.java','.c','.cpp','.h','.hpp','.go','.rb','.php','.rs','.kt','.toml','.gitignore']

    if ext in text_exts or ext == '':
        try:
            text = content.decode('utf-8')
            escaped = text.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
            content_html = f'<pre class="code">{escaped}</pre>'
        except:
            content_html = '<p>Cannot display file</p>'
    elif ext in ['.jpg','.jpeg','.png','.gif','.bmp','.webp','.svg','.ico']:
        content_html = f'<img src="data:image/{ext[1:]};base64,{__import__("base64").b64encode(content).decode()}">'
    elif ext == '.pdf':
        content_html = '<p>PDF - Please download</p>'
    else:
        content_html = '<p>Binary file - Please download</p>'

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{filename}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}}
.container{{max-width:1400px;margin:0 auto}}
.header{{background:#161b22;padding:20px;border-radius:8px;margin-bottom:20px;border:1px solid #30363d}}
h2{{color:#c9d1d9;margin-bottom:12px;word-wrap:break-word;font-size:18px}}
.actions a{{color:#58a6ff;margin-right:16px;text-decoration:none;font-size:14px}}
.actions a:hover{{text-decoration:underline}}
.content{{background:#161b22;padding:20px;border-radius:8px;border:1px solid #30363d;overflow:auto}}
.code{{color:#c9d1d9;font-size:14px;line-height:1.6;white-space:pre-wrap;word-wrap:break-word}}
img{{max-width:100%;height:auto;display:block;border-radius:6px}}
@media(max-width:768px){{
body{{padding:12px}}
.header{{padding:16px}}
h2{{font-size:16px}}
.content{{padding:16px}}
.code{{font-size:13px}}
}}
</style>
</head><body>
<div class="container">
<div class="header">
<h2>{filename}</h2>
<div class="actions"><a href="javascript:history.back()">Back</a><a href="/download{filepath}">Download</a></div>
</div>
<div class="content">{content_html}</div>
</div>
</body></html>"""

def create_zip(root_path, rel_path):
    global SHOW_HIDDEN
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        if rel_path:
            start_path = os.path.join(root_path, rel_path)
            arc_root = os.path.basename(rel_path)
        else:
            start_path = root_path
            arc_root = os.path.basename(root_path)

        for root, dirs, files in os.walk(start_path):
            if not SHOW_HIDDEN:
                dirs[:] = [d for d in dirs if not d.startswith('.')]
            for file in files:
                if not SHOW_HIDDEN and file.startswith('.'):
                    continue
                file_path = os.path.join(root, file)
                arc_name = os.path.join(arc_root, os.path.relpath(file_path, start_path))
                try:
                    zf.write(file_path, arc_name)
                except:
                    pass

    zip_buffer.seek(0)
    return zip_buffer

class FileServerHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        path = unquote(self.path.split('?',1)[0])

        if path == '/' or path == '/browse' or path == '/browse/':
            content = generate_directory_listing(BASE_DIR).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        if path.startswith('/browse/'):
            rel_path = path[8:]
            full_path = os.path.normpath(os.path.join(BASE_DIR, rel_path))
            if not full_path.startswith(BASE_DIR):
                self.send_error(403, "Forbidden")
                return
            if os.path.isdir(full_path):
                content = generate_directory_listing(full_path).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        if path.startswith('/view/'):
            rel_path = path[6:]
            full_path = os.path.normpath(os.path.join(BASE_DIR, rel_path))
            if not full_path.startswith(BASE_DIR) or not os.path.isfile(full_path):
                self.send_error(404, "Not found")
                return
            try:
                with open(full_path, 'rb') as f:
                    file_content = f.read()
                html = generate_file_view('/' + rel_path, file_content).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(html)))
                self.end_headers()
                self.wfile.write(html)
            except Exception as e:
                self.send_error(500, str(e))
            return

        if path.startswith('/download/'):
            rel_path = path[10:]
            full_path = os.path.normpath(os.path.join(BASE_DIR, rel_path))
            if not full_path.startswith(BASE_DIR) or not os.path.isfile(full_path):
                self.send_error(404, "Not found")
                return
            try:
                filename = os.path.basename(full_path)
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.send_header('Content-Length', str(os.path.getsize(full_path)))
                self.end_headers()
                with open(full_path, 'rb') as f:
                    shutil.copyfileobj(f, self.wfile)
            except BrokenPipeError:
                pass
            return

        if path.startswith('/download-all'):
            rel_path = path[14:] if len(path) > 14 else ''
            try:
                zip_buffer = create_zip(BASE_DIR, rel_path)
                zip_name = os.path.basename(rel_path) if rel_path else 'archive'
                self.send_response(200)
                self.send_header('Content-Type', 'application/zip')
                self.send_header('Content-Disposition', f'attachment; filename="{zip_name}.zip"')
                self.send_header('Content-Length', str(len(zip_buffer.getvalue())))
                self.end_headers()
                self.wfile.write(zip_buffer.getvalue())
            except Exception as e:
                self.send_error(500, str(e))
            return

        self.send_error(404, "Not found")

if __name__ == "__main__":
    response = input("Show hidden files (files starting with .)? [y/N]: ").strip().lower()
    SHOW_HIDDEN = response == 'y' or response == 'yes'

    socketserver.TCPServer.allow_reuse_address = True

    with socketserver.TCPServer(("", PORT), FileServerHandler) as httpd:
        url = f"http://127.0.0.1:{PORT}/"
        print(f"\nServer: {url}")
        print(f"Root: {BASE_DIR}")
        print(f"Hidden: {'Yes' if SHOW_HIDDEN else 'No'}")
        print("Ctrl-C to stop\n")
        try:
            webbrowser.open(url)
        except:
            pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nDone.")
            httpd.server_close()
