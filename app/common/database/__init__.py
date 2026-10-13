from app.common.config import DatabaseConfig
from app.common.database.postgres import Postgres

db = Postgres(DatabaseConfig.from_env())