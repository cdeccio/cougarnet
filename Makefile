.PHONY: update build install install-deps

build:
	python3 setup.py build

update:
	git pull

install:
	sudo python3 setup.py install

install-deps:
	sudo apt install openvswitch-switch lxterminal python3-pygraphviz libgraph-easy-perl wireshark socat
