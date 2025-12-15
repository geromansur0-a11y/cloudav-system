# CloudAV - Multiplatform Cloud Antivirus

Sistem antivirus cloud lengkap dengan agen Python cross-platform dan dashboard HTML5.

## Quick Deploy
1. Fork repo ini
2. Deploy API ke Railway/Render (gratis)
3. Jalankan agen di PC: `python agent.py`
4. Buka dashboard: `https://your-app.railway.app`

# 1. Buat repo GitHub, upload semua file ini
# 2. Deploy ke Railway (gratis):
#    - railway.app → New Project → Deploy from GitHub
#    - Pilih repo ini → Deploy

# 3. Update URL di agent.py dan ui/index.html
#    Ganti "https://your-app.railway.app" dengan URL Railway

# 4. Build & Run Agent:
cd agent
pip install -r requirements.txt
python agent.py

# 5. Atau build executable:
pyinstaller --onefile --name CloudAV agent.py

