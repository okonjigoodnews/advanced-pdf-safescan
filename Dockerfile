FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY . .

ENV APP_HOST=0.0.0.0
ENV APP_PORT=8008

EXPOSE 8008
EXPOSE 8501

CMD ["waitress-serve", "--host=0.0.0.0", "--port=8008", "--call", "wsgi:create_app"]
