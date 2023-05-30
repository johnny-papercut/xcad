FROM python:3.11-slim

WORKDIR .
COPY . .

RUN apt-get update && apt-get install git libgl1-mesa-glx libglib2.0-0 -y

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

EXPOSE 8080

CMD exec gunicorn --bind :8080 --workers 1 --timeout 3600 --threads 8 main:api --access-logfile - --log-level info
