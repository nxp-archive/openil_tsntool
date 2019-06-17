This demo shows the timestamping frames by web every second.

How to Make
-----------
Just run 'make' at this folder to get enetctscap.

How to run at OpenIL
--------------------
Suppose run capture the timestamp at eno2, and web brower tracking at eno0 port.

Copy the folder ./webserver to OpenIL one folder.
Run the 'startcapture.sh eno2' at boards.

ifconfig to check the eno0 ip address(10.193.20.71 as example). 
Web browser open url:
http://10.193.20.71:8180/


Run Qbv Enable
--------------
Set a cycletime is 100ms.

>tsntool

tsntool> qbvset --device eno2 --entryfile qbv1.txt --basetime 100000000

You can modify the qbv1.txt. Suggest the cycletime is times of 100ms.

Stop Demo
---------
Run script 'stopcapture.sh'

Capture Receiving Frames Timestamping Only
------------------------------------------
Modify the startcapture.sh with 'enetctscap' command to:

./enetctscap -i $1 -r &
