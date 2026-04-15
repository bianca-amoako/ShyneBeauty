import os

from shyne_app import *  # noqa: F401,F403
from shyne_app.app import app
from shyne_app.config import env_flag

if __name__ == "__main__":
    app.run(host="localhost", port=8000, debug=env_flag("FLASK_DEBUG", default=False))
