from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from app.common.config import DatabaseConfig


# SQLAlchemy Engine tự quản lý connection pool. create_engine() chưa lập tức mở toàn bộ các kết nối PostgreSQL
# kết nối được tạo khi ứng dụng thực sự cần sử dụng
class Postgres:

    def __init__(self, config: DatabaseConfig):
        self.engine: Engine = create_engine(
            url=config.url,
            pool_size=config.pool_size,
            max_overflow=config.max_overflow,
            pool_timeout=config.pool_timeout,
            pool_recycle=config.pool_recycle,
            pool_pre_ping=True,
            connect_args={"connect_timeout": config.connect_timeout},
            echo=config.echo,
            hide_parameters=True
        )

    def connect(self):
        """Get a connection for SELECT queries."""
        return self.engine.connect()

    def transaction(self):
        """Get a connection with an automatic commit / rollback."""
        return self.engine.begin()

    def ping(self) -> bool:
        """Check PostgreSQL connectivity."""
        with self.connect() as conn:
            return conn.execute(text("SELECT 1")).scalar_one() == 1

    def close(self):
        """Dispose idle connections in the pool."""
        self.engine.dispose()
