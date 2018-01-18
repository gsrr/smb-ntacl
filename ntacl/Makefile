all:
	python setup.py /usr/local install --install-purelib=./ -f
	python /usr/local/NAS/misc/HAAgent/testHA.py 99 ntacllib
	python /usr/local/NAS/misc/HAAgent/testHA.py 99 userOperation
	systemctl restart nascli
	rpm -ivh --force libtalloc-2.1.6-1.el7.x86_64.rpm
	rpm -ivh --force pytalloc-2.1.6-1.el7.x86_64.rpm
	yum -y install pyldb

clean:
	rm -rf ./build
	rm -rf files.txt

