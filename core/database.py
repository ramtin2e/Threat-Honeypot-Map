import os
import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class Attack(Base):
    __tablename__ = 'attacks'

    id = Column(Integer, primary_key=True)
    session_id = Column(String(50), nullable=True) # UUID to group SSH commands
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    source_ip = Column(String(50))
    geo_location = Column(String(100)) # e.g., "China", "Russia", "USA"
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    port = Column(Integer)
    protocol = Column(String(20)) # e.g., "SSH", "HTTP"
    payload = Column(String(500)) # e.g., command executed, or HTTP path
    mitre_tags = Column(String(200)) # e.g., "T1033, T1003"
    risk_score = Column(Integer, default=0) # 0-100 threat score
    threat_label = Column(String(100), nullable=True) # e.g., "Known Botnet"
    file_hash = Column(String(64), nullable=True) # SHA256 of downloaded payload
    action_taken = Column(String(50), default="LOGGED") # SOAR action (e.g., BLOCKED)

# Setup the engine and session
db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'honeypot.db')
engine = create_engine(f'sqlite:///{db_path}', echo=False)

# Create tables if they don't exist
Base.metadata.create_all(engine)

SessionLocal = sessionmaker(bind=engine)

def get_db_session():
    return SessionLocal()
