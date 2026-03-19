@echo off
chcp 65001 >nul 2>&1
echo ============================================================
echo   WiFi握手包捕获工具 - 打包为EXE
echo ============================================================
echo.

:: 检查Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] 未检测到Python，请先安装Python 3.8+
    pause
    exit /b 1
)

:: 安装依赖
echo [1/3] 安装依赖...
pip install pyinstaller scapy -q

:: 打包
echo [2/3] PyInstaller打包中...
pyinstaller --onefile --console --name "WiFi握手包捕获" --icon=NONE capture.py

:: 检查结果
echo.
if exist "dist\WiFi握手包捕获.exe" (
    echo [OK] 打包成功!
    echo     文件: dist\WiFi握手包捕获.exe
    echo     大小: 
    for %%F in ("dist\WiFi握手包捕获.exe") do echo     %%~zF bytes
    echo.
    echo 使用方法:
    echo   1. 右键 "WiFi握手包捕获.exe" → 以管理员身份运行
    echo   2. 选择 "1. 扫描附近WiFi"
    echo   3. 选择目标WiFi编号
    echo   4. 等待捕获完成，复制hashline
) else (
    echo [!] 打包失败，请检查错误信息
)

echo.
pause
