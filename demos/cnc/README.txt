INSTALL:
--------
Suppose you are installing the demo on a Centos PC or Ubuntu PC
as the webserver.

CNC demo require python3 and related libs:pyang libnetconf and libssh.
(refer Openil UG Chapter NETCONF/YANG 5.4).

libnetconf need to add a patch to fix the demo python support.

libnetconf commit point:
commit 62a983a3f6259107619128f4a850188b8f420b8b
Author: Michal Vasko <mvasko@cesnet.cz>
Date:   Tue Oct 18 10:14:24 2016 +0200

    BUGFIX copy-paste error

patching two patches:
git am 0001-lnctool-to-make-install-transapi-yang-model-proper.patch
git am 0002-automatic-python3-authorizing-with-root-password-non.patch

Then compile the python lib:
cd libnetconf/python;
python3 setup.py build; python3 setup.py install;
(if rebuild, you need to remove the folder rm build -rf before rebuild)

AVAHI DAEMON INSTALL:
-------------
Except those libs. Below libs and deamon also be required for both
server and client side(take Centos7.2 as example):

sudo yum install nss-mdns avahi avahi-tools

Setup avahi daemon disable the ipv6:

/etc/avahi/avahi-daemon.conf
use-ipv6=no
publish-a-on-ipv6=no

sudo systemctl start avahi-daemon.service

OPENIL BOARDS:
--------------
On the OpenIL board, avahi-daemon and netopeer server are required:
BR2_PACKAGE_AVAHI=y
BR2_PACKAGE_AVAHI_AUTOIPD=y
BR2_PACKAGE_AVAHI_DAEMON=y
BR2_PACKAGE_AVAHI_LIBDNSSD_COMPATIBILITY=y
BR2_PACKAGE_NSS_MDNS=y
BR2_PACKAGE_NETOPEER=y

RUN:
----
run the webserver at the PC side.
sudo python3 cnc.py
Open a browser in local domain machine.
Input the ip of webserver PC:
http://10.193.20.147:8180


Docker Run:
You could not to install the softwares as up steps. Replace by running a docker image:
Just to run:

docker run  --net=host -t -i liupoer/cncdemo:v1 /bin/bash /etc/rc.d/rc.local

HISTORY:
v1: Support Qbv and Qbu setting.
    Recommend to check the boards with tsntool to check the real configure
    for comparation.

