FROM tiangolo/uvicorn-gunicorn-fastapi:python3.7

COPY ./requirements.txt /requirements.txt
RUN pip install -r /requirements.txt
COPY ./worker.py /worker.py
COPY ./app/prestart.sh /app
COPY ./app /app/app
