# IOC Analyzer - Build Scripts

## Available Scripts

### 1. `build.bat` - Production Build
**Purpose**: Build a standalone executable for distribution

**What it does**:
- ✅ Checks Python and pip installation
- ✅ Cleans previous builds
- ✅ Verifies required directories
- ✅ Installs/updates dependencies
- ✅ Builds executable with PyInstaller
- ✅ Verifies build success
- ✅ Shows executable size and location

**Usage**:
```batch
build.bat
```

**Output**: `dist\IOC_Analyzer.exe`

---

### 2. `dev.bat` - Development Mode
**Purpose**: Quick start for development and testing

**What it does**:
- ✅ Checks Python installation
- ✅ Installs dependencies if needed
- ✅ Creates required directories
- ✅ Runs the application in development mode

**Usage**:
```batch
dev.bat
```

**Note**: Press `Ctrl+C` to stop the server

---

### 3. `clean.bat` - Cleanup
**Purpose**: Remove build artifacts and cache files

**What it does**:
- ✅ Removes `build` directory
- ✅ Removes `dist` directory
- ✅ Removes `__pycache__` directories
- ✅ Removes `.pyc` files
- ✅ Removes backup spec files

**Usage**:
```batch
clean.bat
```

**Note**: Log and result files are preserved by default

---

## Build Process Workflow

### For Development:
1. Run `dev.bat` to start the application
2. Make your changes
3. Test in the browser
4. Repeat

### For Production:
1. Run `clean.bat` to remove old builds
2. Run `build.bat` to create executable
3. Test `dist\IOC_Analyzer.exe`
4. Distribute the executable

---

## Requirements

- **Python**: 3.8 or higher
- **pip**: Latest version
- **Dependencies**: Listed in `requirements.txt`
  - Flask==2.3.3
  - requests==2.31.0
  - pyinstaller==5.13.2
  - cryptography==41.0.7
  - keyring==24.2.0

---

## Build Configuration

### `ioc_analyzer.spec`
PyInstaller configuration file with:

**Included**:
- `templates/` - HTML templates
- `static/` - CSS, JS, images
- `keyring` - Secure credential storage
- `cryptography` - Encryption support
- `logging` - Application logging

**Excluded** (to reduce size):
- `tkinter` - GUI framework (not used)
- `matplotlib` - Plotting library (not used)
- `numpy` - Numerical library (not used)
- `pandas` - Data analysis (not used)
- `PIL` - Image processing (not used)
- `PyQt5` - GUI framework (not used)
- `scipy` - Scientific computing (not used)

---

## Troubleshooting

### Build fails with "Python not found"
**Solution**: Install Python 3.8+ and add to PATH

### Build fails with "pip not found"
**Solution**: Install pip or reinstall Python with pip

### Build fails with dependency errors
**Solution**: Run `pip install -r requirements.txt` manually

### Executable doesn't run
**Solution**: 
1. Check if antivirus is blocking it
2. Run from command line to see errors
3. Rebuild with `clean.bat` then `build.bat`

### Executable is too large
**Solution**: The spec file already excludes unused packages. Size is normal for a Flask application (~30-50 MB)

---

## Directory Structure

```
ioc-analyzer/
├── app.py                  # Main application
├── build.bat              # Production build script
├── dev.bat                # Development script
├── clean.bat              # Cleanup script
├── ioc_analyzer.spec      # PyInstaller config
├── requirements.txt       # Python dependencies
├── icon.ico              # Application icon
├── templates/            # HTML templates
├── static/               # CSS, JS, images
├── logs/                 # Application logs (auto-created)
├── results/              # Analysis results (auto-created)
├── build/                # Build artifacts (temporary)
└── dist/                 # Final executable
```

---

## Notes

- The executable is **portable** - no installation required
- First run will create `logs/` and `results/` directories
- API key is stored securely using Windows Credential Manager
- Logs are rotated automatically (5MB max, 5 backups)
- Results are saved as JSON files with timestamps

---

## Version Information

- **Application**: IOC Analyzer
- **Build System**: PyInstaller 5.13.2
- **Python**: 3.8+
- **Platform**: Windows
