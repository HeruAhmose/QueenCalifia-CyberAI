"""QC OS — Settings (frozen dataclass, merged)"""
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ORIGINS = [
    "http://localhost:5173", "http://localhost:4173",
    "https://queencalifia-cyberai.web.app", "https://queencalifia-cyberai.firebaseapp.com",
]

@dataclass(frozen=True)
class Settings:
    name: str; persona: str; db_path: Path; cors_origins: str
    max_message_chars: int; admin_key: str; enable_trading: bool
    api_key: str
    sec_user_agent: str; fred_api_key: str; nasdaq_api_key: str
    default_macro_series: str; ecb_base_url: str
    coinbase_base_url: str; kraken_base_url: str
    cache_ttl_minutes: int; quantum_backend: str

def get_settings() -> Settings:
    return Settings(
        name=os.getenv("QC_NAME", "Queen Califia"),
        persona=os.getenv("QC_PERSONA", "Sovereign, strategic, calm, precise, memory-aware, and protective."),
        db_path=Path(os.getenv("QC_DB_PATH", "data/qc_os.db")),
        cors_origins=os.getenv("QC_CORS_ORIGINS", ",".join(DEFAULT_ORIGINS)),
        max_message_chars=int(os.getenv("QC_MAX_MESSAGE_CHARS", "4000")),
        admin_key=os.getenv("QC_ADMIN_KEY", ""),
        enable_trading=os.getenv("QC_ENABLE_TRADING", "false").lower() == "true",
        api_key=os.getenv("QC_API_KEY", ""),
        sec_user_agent=os.getenv("QC_SEC_USER_AGENT", "QueenCalifia/4.2 aitconsult22@gmail.com"),
        fred_api_key=os.getenv("FRED_API_KEY", ""),
        nasdaq_api_key=os.getenv("NASDAQ_API_KEY", ""),
        default_macro_series=os.getenv("QC_DEFAULT_MACRO_SERIES", "FEDFUNDS"),
        ecb_base_url=os.getenv("QC_ECB_BASE_URL", "https://data-api.ecb.europa.eu/service/data"),
        coinbase_base_url=os.getenv("QC_COINBASE_BASE_URL", "https://api.exchange.coinbase.com"),
        kraken_base_url=os.getenv("QC_KRAKEN_BASE_URL", "https://api.kraken.com"),
        cache_ttl_minutes=int(os.getenv("QC_CACHE_TTL_MINUTES", "15")),
        quantum_backend=os.getenv("QC_QUANTUM_BACKEND", "simulator"),
    )

def parse_origins(raw: str) -> list[str]:
    return [i.strip() for i in raw.split(",") if i.strip()] or DEFAULT_ORIGINS
