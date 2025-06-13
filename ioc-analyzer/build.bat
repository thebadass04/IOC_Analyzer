@echo off
REM build.bat

echo 🔧 Installing dependencies...
pip install -r requirements.txt

echo 🧪 Testing setup...
python test_setup.py

echo 🏗️ Building executable...
pyinstaller --clean ioc_analyzer.spec

echo ✅ Build complete!
echo 📁 Executable location: dist\IOC_Analyzer.exe

pause