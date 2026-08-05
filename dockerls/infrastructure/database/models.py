from __future__ import annotations

from sqlalchemy import Column, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    pass


class CacheEntry(Base):
    __tablename__ = "cache_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(512), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=False)
    expires_at = Column(Float, nullable=False)


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    image_reference = Column(String(512), nullable=False, index=True)
    scanner = Column(String(64), nullable=False)
    result_json = Column(Text, nullable=False)
    scanned_at = Column(Float, nullable=False)


def create_db_engine(db_path: str) -> tuple:
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    return engine, factory
