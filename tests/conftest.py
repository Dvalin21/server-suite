"""
tests/conftest.py
=================
Provides stub modules for runtime deps not available in test environment.
On the actual server, real packages (rich, flask, etc.) will be installed.
"""
import sys
import types

def make_stub(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    return m

# Stub rich
def _noop(*a, **kw): return None
def _pass_through(x): return x
def _true(*a, **kw): return True

for mod_name in [
    "rich", "rich.console", "rich.panel", "rich.table",
    "rich.prompt", "rich.columns", "rich.progress",
]:
    stub = make_stub(mod_name)
    stub.Console   = lambda: type("C", (), {"print": _noop, "__enter__": lambda s: s, "__exit__": _noop})()
    stub.Panel     = type("Panel", (), {"__init__": _noop})
    stub.Table     = type("Table", (), {"__init__": _noop, "add_row": _noop, "add_column": _noop})
    stub.Prompt    = type("Prompt", (), {"ask": staticmethod(lambda *a, **kw: "")})
    stub.Confirm   = type("Confirm", (), {"ask": staticmethod(lambda *a, **kw: False)})
    stub.Columns   = type("Columns", (), {"__init__": _noop})
    stub.Progress  = type("Progress", (), {"__init__": _noop, "__enter__": lambda s: s, "__exit__": _noop})
    stub.SpinnerColumn = type("SC", (), {"__init__": _noop})
    stub.TextColumn    = type("TC", (), {"__init__": _noop})
    stub.BarColumn     = type("BC", (), {"__init__": _noop})
    stub.print     = _noop
    sys.modules.setdefault(mod_name, stub)

# Stub flask
flask_stub = make_stub("flask")
flask_stub.Flask    = type("Flask", (), {"__init__": _noop, "route": _noop, "secret_key": ""})
flask_stub.render_template = _noop
flask_stub.request  = type("R", (), {"method": "GET", "json": {}, "remote_addr": "127.0.0.1"})()
flask_stub.jsonify  = lambda x: x
flask_stub.session  = {}
for sub in ["flask"]:
    sys.modules.setdefault(sub, flask_stub)

# Stub flask_socketio
sio_stub = make_stub("flask_socketio")
sio_stub.SocketIO = type("SocketIO", (), {"__init__": _noop, "emit": _noop, "on": lambda *a, **kw: _pass_through})
sio_stub.emit     = _noop
sys.modules.setdefault("flask_socketio", sio_stub)

# Stub eventlet
for m in ["eventlet", "eventlet.wsgi"]:
    sys.modules.setdefault(m, make_stub(m))

# Stub cryptography
for m in ["cryptography", "cryptography.fernet", "cryptography.hazmat",
          "cryptography.hazmat.primitives", "cryptography.hazmat.primitives.kdf",
          "cryptography.hazmat.primitives.kdf.pbkdf2",
          "cryptography.hazmat.primitives.hashes",
          "cryptography.hazmat.backends"]:
    stub = make_stub(m)
    stub.Fernet       = type("Fernet", (), {
        "__init__": _noop,
        "generate_key": staticmethod(lambda: b"dummykey" * 4),
        "encrypt": lambda s, d: d,
        "decrypt": lambda s, d: d,
    })
    stub.PBKDF2HMAC   = type("P", (), {"__init__": _noop, "derive": lambda s, d: b"key"})
    stub.SHA256       = type("S", (), {})
    stub.default_backend = lambda: None
    sys.modules.setdefault(m, stub)
