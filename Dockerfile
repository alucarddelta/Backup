FROM debian:latest

WORKDIR /app

COPY . /app

RUN apt-get update && apt-get install -y build-essential libssl-dev libffi-dev python3 python-dev python-pip

RUN pip install --trusted-host pypi.python.org -r requirements.txt

CMD ["python", "nagios.py"]
