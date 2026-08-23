"""
Silk Road Trading - Backend
----------------------------
API para el panel P2P USDT/DOP. Reemplaza window.storage (que solo funciona
dentro de Claude.ai) por una base de datos real, para que el frontend
funcione desde Blogger, el celular, o donde sea.

Deploy en Render:
  1. Subí esta carpeta a un repo de GitHub.
  2. En Render: New -> Web Service -> conectá el repo.
  3. Build command:  pip install -r requirements.txt
  4. Start command:  uvicorn main:app --host 0.0.0.0 --port $PORT
  5. Variables de entorno (Render -> Environment):
       ADMIN_PASSWORD   -> tu clave de admin (NO la pongas en el código)
       SECRET_KEY       -> cualquier string largo random, para firmar tokens
       CORS_ORIGINS     -> https://tublog.blogspot.com,https://otra-url.com
       DATABASE_URL     -> (opcional) postgresql://... si usás Postgres.
                            Si no la ponés, usa SQLite local (silkroad.db).
                            OJO: en Render free tier el disco es efímero,
                            si el servicio se reinicia se pierde la data en
                            SQLite. Para producción real, usá Postgres
                            (Render tiene un plan free de Postgres) igual
                            que ya hiciste con Silk Miner.
"""

import os
import time
import hashlib
import secrets
from datetime import datetime
from typing import Optional, List

import requests
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import (
    create_engine, Column, String, Float, Integer, DateTime, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# ---------- CONFIG ----------
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "cambia-esta-clave")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./silkroad.db")
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")
TOKEN_MAX_AGE = 60 * 60 * 12  # 12 horas

serializer = URLSafeTimedSerializer(SECRET_KEY)

# ---------- DB SETUP ----------
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Empleado(Base):
    __tablename__ = "empleados"
    id = Column(String, primary_key=True)
    nombre = Column(String, nullable=False)
    pin_hash = Column(String, nullable=False)
    comision = Column(Float, default=30.0)


class Lote(Base):
    __tablename__ = "lotes"
    id = Column(Integer, primary_key=True, autoincrement=True)
    emp_id = Column(String, ForeignKey("empleados.id"), nullable=False)
    monto_usdt = Column(Float, nullable=False)
    precio_compra = Column(Float, nullable=False)
    precio_venta_objetivo = Column(Float, nullable=False)
    fecha = Column(DateTime, nullable=False)
    precio_venta = Column(Float, nullable=True)
    fecha_venta = Column(DateTime, nullable=True)
    estado = Column(String, default="activo")


class PrecioSnapshot(Base):
    __tablename__ = "precio_snapshots"
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    compra_mejor = Column(Float, nullable=True)
    compra_promedio = Column(Float, nullable=True)
    venta_mejor = Column(Float, nullable=True)
    venta_promedio = Column(Float, nullable=True)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------- SCHEMAS ----------
class AdminLoginIn(BaseModel):
    password: str


class EmpleadoLoginIn(BaseModel):
    id: str
    pin: str


class EmpleadoCreateIn(BaseModel):
    id: str
    nombre: str
    pin: str
    comision: float = 30.0


class LoteCreateIn(BaseModel):
    emp_id: str
    monto_usdt: float
    precio_compra: float
    precio_venta_objetivo: float
    fecha: datetime


class VentaIn(BaseModel):
    fecha_venta: datetime
    precio_venta: Optional[float] = None  # si es None, se usa el objetivo


# ---------- HELPERS: passwords / tokens ----------
def hash_pin(pin: str) -> str:
    salt = secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 100_000).hex()
    return f"{salt}${h}"


def verify_pin(pin: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$")
    except ValueError:
        return False
    check = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 100_000).hex()
    return secrets.compare_digest(check, h)


def make_token(role: str, emp_id: Optional[str] = None) -> str:
    return serializer.dumps({"role": role, "id": emp_id})


def read_token(authorization: Optional[str]) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Falta token de autenticación.")
    token = authorization.split(" ", 1)[1]
    try:
        data = serializer.loads(token, max_age=TOKEN_MAX_AGE)
    except SignatureExpired:
        raise HTTPException(401, "Sesión expirada, iniciá sesión de nuevo.")
    except BadSignature:
        raise HTTPException(401, "Token inválido.")
    return data


def require_admin(authorization: Optional[str] = Header(None)) -> dict:
    data = read_token(authorization)
    if data.get("role") != "admin":
        raise HTTPException(403, "Requiere permisos de admin.")
    return data


def require_session(authorization: Optional[str] = Header(None)) -> dict:
    return read_token(authorization)


# ---------- APP ----------
app = FastAPI(title="Silk Road Trading API")

origins = [o.strip() for o in CORS_ORIGINS.split(",")] if CORS_ORIGINS != "*" else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"ok": True, "service": "silk-road-trading-api"}


# ---------- BINANCE P2P PROXY ----------
BINANCE_P2P_URL = "https://p2p.binance.com/bapi/c2c/v2/friendly/c2c/adv/search"
_precio_cache = {"data": None, "ts": 0}
PRECIO_CACHE_TTL = 45  # segundos, para no golpear a Binance en cada refresh


def _fetch_binance_side(trade_type: str, rows: int = 10):
    """
    trade_type: 'BUY' (nosotros comprando USDT, vemos anuncios de venta de otros)
                'SELL' (nosotros vendiendo USDT, vemos anuncios de compra de otros)
    """
    payload = {
        "asset": "USDT",
        "fiat": "DOP",
        "tradeType": trade_type,
        "page": 1,
        "rows": rows,
        "payTypes": [],
        "publisherType": None,
    }
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SilkRoadTrading/1.0",
    }
    resp = requests.post(BINANCE_P2P_URL, json=payload, headers=headers, timeout=8)
    resp.raise_for_status()
    data = resp.json()
    anuncios = data.get("data", [])
    if not anuncios:
        return None
    precios = [float(a["adv"]["price"]) for a in anuncios]
    return {
        "mejor": precios[0],
        "promedio": round(sum(precios) / len(precios), 4),
        "cantidad_anuncios": len(precios),
    }


@app.get("/api/precio-p2p")
def precio_p2p(db: Session = Depends(get_db), _=Depends(require_session)):
    now = time.time()
    if _precio_cache["data"] and (now - _precio_cache["ts"]) < PRECIO_CACHE_TTL:
        return _precio_cache["data"]

    try:
        # BUY = anuncios donde OTROS venden USDT = precio al que NOSOTROS compramos
        compra = _fetch_binance_side("BUY")
        # SELL = anuncios donde OTROS compran USDT = precio al que NOSOTROS vendemos
        venta = _fetch_binance_side("SELL")
    except Exception as e:
        raise HTTPException(502, f"No se pudo consultar Binance P2P ahora mismo: {e}")

    if not compra or not venta:
        raise HTTPException(502, "Binance no devolvió anuncios para USDT/DOP en este momento.")

    result = {
        "compra": compra,
        "venta": venta,
        "timestamp": datetime.utcnow().isoformat(),
    }

    # guardamos snapshot para el historial de mejores horarios/días
    snap = PrecioSnapshot(
        compra_mejor=compra["mejor"], compra_promedio=compra["promedio"],
        venta_mejor=venta["mejor"], venta_promedio=venta["promedio"],
    )
    db.add(snap)
    db.commit()

    _precio_cache["data"] = result
    _precio_cache["ts"] = now
    return result


@app.get("/api/precio-p2p/historial")
def precio_p2p_historial(db: Session = Depends(get_db), _=Depends(require_admin)):
    snaps = db.query(PrecioSnapshot).order_by(PrecioSnapshot.timestamp.desc()).limit(500).all()
    return [{
        "timestamp": s.timestamp.isoformat(),
        "compraMejor": s.compra_mejor,
        "compraPromedio": s.compra_promedio,
        "ventaMejor": s.venta_mejor,
        "ventaPromedio": s.venta_promedio,
    } for s in snaps]


# ---------- AUTH ----------
# TEMPORAL: la verificación de clave/PIN está desactivada para poder probar
# el resto del panel sin trabarse. Cuando todo lo demás funcione bien,
# volvemos a activar esto (avisale a Claude "reactivá el login").
@app.post("/api/auth/admin")
def login_admin(body: AdminLoginIn):
    return {"token": make_token("admin")}


@app.post("/api/auth/empleado")
def login_empleado(body: EmpleadoLoginIn, db: Session = Depends(get_db)):
    emp = db.query(Empleado).filter(Empleado.id == body.id).first()
    if not emp:
        raise HTTPException(401, "Ese ID de empleado no existe.")
    return {
        "token": make_token("empleado", emp.id),
        "id": emp.id,
        "nombre": emp.nombre,
        "comision": emp.comision,
    }


# ---------- EMPLEADOS (admin) ----------
@app.get("/api/empleados")
def listar_empleados(db: Session = Depends(get_db), _=Depends(require_admin)):
    emps = db.query(Empleado).all()
    return [{"id": e.id, "nombre": e.nombre, "comision": e.comision} for e in emps]


@app.post("/api/empleados")
def crear_empleado(body: EmpleadoCreateIn, db: Session = Depends(get_db), _=Depends(require_admin)):
    if db.query(Empleado).filter(Empleado.id == body.id).first():
        raise HTTPException(400, "Ese ID ya existe.")
    emp = Empleado(id=body.id, nombre=body.nombre, pin_hash=hash_pin(body.pin), comision=body.comision)
    db.add(emp)
    db.commit()
    return {"ok": True}


@app.delete("/api/empleados/{emp_id}")
def borrar_empleado(emp_id: str, db: Session = Depends(get_db), _=Depends(require_admin)):
    emp = db.query(Empleado).filter(Empleado.id == emp_id).first()
    if emp:
        db.delete(emp)
        db.commit()
    return {"ok": True}


# ---------- LOTES ----------
def lote_to_dict(l: Lote) -> dict:
    return {
        "id": l.id,
        "empId": l.emp_id,
        "montoUSDT": l.monto_usdt,
        "precioCompra": l.precio_compra,
        "precioVentaObjetivo": l.precio_venta_objetivo,
        "fecha": l.fecha.isoformat(),
        "precioVenta": l.precio_venta,
        "fechaVenta": l.fecha_venta.isoformat() if l.fecha_venta else None,
        "estado": l.estado,
    }


@app.get("/api/lotes")
def listar_lotes(db: Session = Depends(get_db), session=Depends(require_session)):
    q = db.query(Lote)
    if session["role"] == "empleado":
        q = q.filter(Lote.emp_id == session["id"])
    return [lote_to_dict(l) for l in q.all()]


@app.post("/api/lotes")
def crear_lote(body: LoteCreateIn, db: Session = Depends(get_db), _=Depends(require_admin)):
    if not db.query(Empleado).filter(Empleado.id == body.emp_id).first():
        raise HTTPException(400, "Ese empleado no existe.")
    lote = Lote(
        emp_id=body.emp_id,
        monto_usdt=body.monto_usdt,
        precio_compra=body.precio_compra,
        precio_venta_objetivo=body.precio_venta_objetivo,
        fecha=body.fecha,
        estado="activo",
    )
    db.add(lote)
    db.commit()
    return {"ok": True, "id": lote.id}


@app.post("/api/lotes/{lote_id}/vender")
def vender_lote(lote_id: int, body: VentaIn, db: Session = Depends(get_db), session=Depends(require_session)):
    lote = db.query(Lote).filter(Lote.id == lote_id).first()
    if not lote:
        raise HTTPException(404, "Lote no encontrado.")
    if session["role"] == "empleado" and lote.emp_id != session["id"]:
        raise HTTPException(403, "Ese lote no es tuyo.")
    if lote.precio_venta is not None:
        raise HTTPException(400, "Ese lote ya fue reportado como vendido.")
    lote.precio_venta = body.precio_venta if body.precio_venta is not None else lote.precio_venta_objetivo
    lote.fecha_venta = body.fecha_venta
    lote.estado = "cerrado"
    db.commit()
    return {"ok": True}


@app.delete("/api/lotes/{lote_id}")
def borrar_lote(lote_id: int, db: Session = Depends(get_db), _=Depends(require_admin)):
    lote = db.query(Lote).filter(Lote.id == lote_id).first()
    if lote:
        db.delete(lote)
        db.commit()
    return {"ok": True}
