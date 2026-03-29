import os
import subprocess
import sys


def main():
    os.environ.setdefault("PYTHONPATH", os.path.dirname(__file__))
    cmd = [sys.executable, "-m", "streamlit", "run", "dashboard/app.py"]
    subprocess.run(cmd)


if __name__ == "__main__":
    main()
