FROM python:3.13
ADD ./src/ /code
WORKDIR /code
CMD python server.py