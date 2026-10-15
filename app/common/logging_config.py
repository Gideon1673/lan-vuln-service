import logging

from rich.console import Console
from rich.logging import RichHandler


class ShortNameFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.shortname = record.name.split(".")[-1]
        return True


def setup_logging(level=logging.INFO):
    console = Console(force_terminal=True, color_system="truecolor", width=180)

    handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        show_time=True,
        show_level=True,
        show_path=False,
        markup=True
    )

    handler.addFilter(ShortNameFilter())

    handler.setFormatter(logging.Formatter("[cyan]%(shortname)-18s[/cyan] | %(message)s"))

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)
    root.addHandler(handler)

    logging.getLogger("pika").setLevel(logging.WARNING)
