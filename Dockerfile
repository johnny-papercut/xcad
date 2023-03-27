FROM python:3.11-alpine3.16

WORKDIR .
COPY . .

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

EXPOSE 8080

CMD exec gunicorn --bind :8080 --workers 3 --timeout 3600 --threads 8 main:api
