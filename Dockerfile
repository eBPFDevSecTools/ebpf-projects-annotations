#Author: Sayandeep Sen (sayandes@in.ibm.com)
#Author: Palani Kodeswaran (palani.kodeswaran@in.ibm.com)

FROM ubuntu:latest

#install dependencies for codequery
RUN apt-get update && apt-get upgrade && apt-get dist-upgrade && apt-get install -y \ 
	build-essential \
	g++ \
	git \
	cmake \
	ninja-build \
	sqlite3 \
	libsqlite3-dev \
	cscope \
	wget \
	python3 \
	python3-pip \
	exuberant-ctags \
	vim 
i
#install python dependencies
RUN python3 -m pip install command
RUN python3 -m pip install pytest-shutil
RUN python3 -m pip install argparse
RUN python3 -m pip install lxml
RUN python3 -m pip install tinydb

#install txl
WORKDIR /root
RUN mkdir /root/deps

RUN wget -O /tmp/txl.tgz  https://www.txl.ca/download/15372-txl10.8b.linux64.tar.gz
RUN tar -xvzf '/tmp/txl.tgz' --strip-components 1 --one-top-level=/root/deps/txl -C .
RUN ls /root
WORKDIR /root/deps/txl
RUN ./InstallTxl

#add annotation code 
WORKDIR /root
ADD asset asset
ADD src src
ADD run1.sh run1.sh
ADD op op
ADD examples examples
#RUN ./run.sh
