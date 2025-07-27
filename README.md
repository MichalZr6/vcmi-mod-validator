# vcmi-mod-validator

A standalone script for validating VCMI mod JSON files.

The script reads and validates mod configuration against official VCMI schemas, and optionally auto-fixes formatting issues. It supports both local validation (with a cloned VCMI repository) and online schema validation via GitHub.

---

## Installation Guide

### 1. Download the script

- Either download `vcmi-mod-validator.zip` and extract it,
- Or clone the repository:

```bash
git clone https://github.com/MichalZr6/vcmi-mod-validator.git
```

### 2. Install Python

- Download Python from https://www.python.org/downloads/
- During installation, **make sure to check** “Add Python to PATH”.

---

## Running the Script

You can run the script in several ways:

### Option 1: Using PyCharm

1. Download and install [PyCharm](https://www.jetbrains.com/pycharm)  
2. Open `validate_json.py` from the `vcmi-mod-validator` folder  
3. When prompted, open as a **project** (not in lightweight mode)  
4. Let PyCharm create a virtual environment using `requirements.txt`  
5. Configure the interpreter to point to your installed Python (e.g., `python.exe` on Windows)

---

### Option 2: Using Visual Studio Code

1. Download and install [Visual Studio Code](https://code.visualstudio.com/)  
2. Open the `vcmi-mod-validator` folder and select `validate_json.py`  
3. Install the Python extension: open Extensions (`Ctrl+Shift+X`), search for "Python", and click **Install**  
4. Open the Terminal panel (`Ctrl+J`)  
5. Run the following command to install dependencies:

```bash
pip install -r path\to\vcmi-mod-validator\requirements.txt
```

---

### Option 3: Using Command Line / Terminal

1. Open a terminal or command prompt  
2. Navigate to the project directory:

```bash
cd path\to\vcmi-mod-validator
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Configuration

Edit the bottom of `validate_json.py`:

- `INPUT_DIR` – path to your mod or folder with JSON files  
- `LOG_FILE_PATH` – (optional) path to log file. Leave only basename and extension (.txt) so it will spawn in vcmi-mod-validator directory.
- `BASE_PATH` – path to your local VCMI repository (used in `LOCAL_MODE`)

Other flags:

- Set `AUTOFIX = False` to prevent the script from modifying files  
- Set `LOCAL_MODE = False` to use the GitHub VCMI version of base config files instead of local repo

---

## Running the Script

- **PyCharm** – click the **Run** button
- **VS Code** – press `F5`, then select **Python Debugger** and then **Python File**  
- **Command Line** – run:

```bash
python validate_json.py
```
