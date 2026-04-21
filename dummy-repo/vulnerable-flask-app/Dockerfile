FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# VULNERABILITY: running as root in container
ENV FLASK_APP=main.py
ENV FLASK_ENV=development

CMD ["python", "main.py"]
