FROM ubuntu:bionic

ENV DEBIAN_FRONTEND=noninteractive

RUN chmod -R 777 /tmp/

RUN  apt-get update && apt-get install -y \
 software-properties-common socat dsniff git ntpdate python build-essential vim lsof gdb screen python3 python3-setuptools python3-pip npm net-tools libffi-dev

RUN add-apt-repository ppa:certbot/certbot

ENV TZ 'Europe/Rome'
RUN echo $TZ > /etc/timezone && apt-get update && apt-get install -y tzdata && rm -f /etc/localtime && ln -nfs /usr/share/zoneinfo/$TZ /etc/localtime && dpkg-reconfigure -f noninteractive tzdata

RUN apt-get update && apt-get install -y nginx python-certbot-nginx
RUN sed -i 's/# server_names_hash_bucket_size 64;/server_names_hash_bucket_size 64;/g' /etc/nginx/nginx.conf

RUN rm -rf /var/lib/apt/lists/*

RUN npm install -g --unsafe @mdslab/wstun@1.0.11 && npm cache --force clean

RUN pip3 install iotronic-lightningrod

RUN sed -i "s|listen 80 default_server;|listen 50000 default_server;|g" /etc/nginx/sites-available/default
RUN sed -i "s|80 default_server;|50000 default_server;|g" /etc/nginx/sites-available/default

COPY data/lr_configure /usr/local/bin/lr_configure
COPY data/lr_install /usr/local/bin/lr_install
COPY data/lr_checks /usr/local/bin/lr_checks
COPY data/startLR /usr/local/bin/startLR

RUN /usr/local/bin/lr_install

VOLUME /var/lib/iotronic

RUN ln -s /usr/local/bin/wstun /usr/bin/wstun

#CMD [ "/usr/sbin/nginx"]
#CMD [ "/usr/local/bin/lightning-rod"]
CMD ["/usr/local/bin/startLR"]
