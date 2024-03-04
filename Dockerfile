#FROM postgres:latest

#ENV POSTGRES_USER='postgres'
#ENV POSTGRES_PASSWORD='200813'
#EXPOSE 5432


FROM ubuntu:latest

RUN apt-get update -y
RUN apt-get install -y python3-pip python2.7-dev build-essential


ENV SERVER_ADDRESS='0.0.0.0'
ENV SERVER_PORT=8080
ENV POSTGRES_HOST='127.0.0.1'
ENV POSTGRES_USERNAME='postgres'
ENV POSTGRES_PASSWORD='200813'
ENV POSTGRES_DATABASE='bot_users'


COPY . /app
WORKDIR /app
#RUN ./init-database.sh
EXPOSE 8080
RUN pip install -r requirements.txt
CMD ["sh", "-c", "exec python3 -m flask run"]