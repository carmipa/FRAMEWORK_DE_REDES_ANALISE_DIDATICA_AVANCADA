FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV APP_HOST=0.0.0.0 \
    APP_PORT=5000 \
    APP_DEBUG=false \
    APP_LOG_LEVEL=INFO \
    APP_LOG_COLOR=1

EXPOSE 5000

CMD ["python", "main.py"]