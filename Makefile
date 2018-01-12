PACKAGE=adpasswd
VERSION=1.0.0

all:
	./setup.py bdist

install:
	tar xf dist/$(PACKAGE)-$(VERSION).linux-x86_64.tar.gz -C /
	sudo cp adpasswd.desktop /usr/share/applications

uninstall:
	rm -rf /usr/local/lib/python2.7/dist-packages/$(PACKAGE)*
	sudo rm /usr/share/applications/adpasswd.desktop

clean:
	rm -rf adpasswd.egg-info build dist

# vi: ts=8 noet:
