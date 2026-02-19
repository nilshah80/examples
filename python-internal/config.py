import os
from dataclasses import dataclass

from dotenv import load_dotenv


@dataclass
class Config:
    client_id: str
    client_secret: str
    subject: str
    port: int
    sidecar_url: str


def load_config() -> Config:
    load_dotenv()
    return Config(
        client_id=os.getenv("CLIENT_ID", "dev-client"),
        client_secret=os.getenv("CLIENT_SECRET", "DevSec-LwgT7vXGZk2njwglKWZBYW7q1sdNTElTQ!"),
        subject=os.getenv("SUBJECT", "test-user"),
        port=int(os.getenv("PORT", "3506")),
        sidecar_url=os.getenv("SIDECAR_URL", "http://localhost:8141"),
    )
