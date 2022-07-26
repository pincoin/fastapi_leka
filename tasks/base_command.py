import pathlib
import sys


class BaseCommand:
    ROOT_PATH = (pathlib.Path(__file__).parents[1] / "app").absolute()

    def __init__(self):
        sys.path.append(str(self.ROOT_PATH))

        from core.config import settings
        from core.utils import get_logger

        self.settings = settings

        self.logger = get_logger()
        self.logger.debug(f"Run: ENV_STATE={self.ROOT_PATH}/local python {__file__}")

    async def handle(self, *args, **kwargs):
        pass
