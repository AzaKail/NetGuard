# NetGuard.AI — MVP (с нуля)

Это **минимальный рабочий прототип**: агент собирает **агрегированные сетевые метрики** (без содержимого пакетов) и отправляет их на сервер. Сервер сохраняет метрики, считает anomaly score (Isolation Forest) и показывает алёрты в веб-панели.

> Используй только в своей/разрешённой сети.

## Что внутри
- `agent/agent.py` — лёгкий агент (Python + psutil), отправляет JSON в FastAPI.
- `server/app/main.py` — FastAPI ingest + простая веб-панель.
- `server/app/detector.py` — буфер, скейлер + IsolationForest, авто-переобучение.
- `server/app/db.py`, `server/app/models.py` — SQLite база (простая).
- `server/app/templates/index.html` — HTML панель (таблица метрик + алёрты).

## Быстрый старт (Windows / Linux)

### 1) Сервер
```bash
cd server
python -m venv .venv
# Windows:
.venv\Scripts\activate


pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Открой в браузере: http://127.0.0.1:8000

### 2) Агент
В новом терминале:
```bash
cd agent
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

python agent.py --server http://127.0.0.1:8000 --interval 5
```

### Демо-режим (чтобы точно увидел аномалии)
```bash
python agent.py --server http://127.0.0.1:8000 --interval 5 --simulate
```
В `--simulate` агент периодически "подкручивает" метрики, чтобы появились алёрты.

## API
- `POST /ingest` — принять метрику
- `GET /api/metrics?limit=50`
- `GET /api/alerts?limit=20`

## Что можно улучшать дальше (следующий шаг)
- хранение в Postgres/TimescaleDB
- windows 1/5/15 минут на сервере
- объяснимость (top-features, вклад по реконструкционной ошибке для AE)
- RBAC и уведомления (Telegram/email)
