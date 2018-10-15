FROM debian:latest

WORKDIR /app

COPY . /app

RUN apt-get update && apt-get install -y build-essential libssl-dev libffi-dev python python-dev python-pip nagios-nrpe-server nano openssh-server
RUN useradd nrpe && update-rc.d nagios-nrpe-server defaults
RUN pip install --trusted-host pypi.python.org -r requirements.txt
RUN service start sshd

CMD ["python", "nagios.py"]
