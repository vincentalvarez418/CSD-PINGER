import os
import shutil
import subprocess

APP_NAME = "pinger"
EXE_PATH = os.path.join("dist", f"{APP_NAME}.exe")

# 1. Kill the app if it's currently running (prevents "Permission Denied" errors)
if os.name == "nt":  # Windows
    subprocess.run(["taskkill", "/F", "/IM", f"{APP_NAME}.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# 2. Explicitly delete the old EXE if it exists
if os.path.exists(EXE_PATH):
    try:
        os.remove(EXE_PATH)
        print(f"Removed old executable: {EXE_PATH}")
    except PermissionError:
        print(f"Warning: Could not delete {EXE_PATH}. It might be open or running.")

# 3. Clean old builds and folders
for folder in ["build", "dist"]:
    if os.path.exists(folder):
        try:
            shutil.rmtree(folder)
        except PermissionError:
            # If rmtree fails because the folder is locked, we try to keep going
            pass

spec_file = f"{APP_NAME}.spec"
if os.path.exists(spec_file):
    os.remove(spec_file)

# PyInstaller command
cmd = [
    "python",
    "-m",
    "PyInstaller",
    "--onefile",
    "--windowed",
    "--name", APP_NAME,
    "--icon", "assets/images/icon.png",
    "--add-data", "assets;assets",
    "pinger.py"
]

subprocess.run(cmd)

print("\nBuild complete.")
print(f"EXE location: dist/{APP_NAME}.exe")