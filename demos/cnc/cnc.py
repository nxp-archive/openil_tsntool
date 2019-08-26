#!/usr/bin/python3
#
#Copyright 2019 NXP
#

from flask import Flask, render_template, request
from flask import jsonify
from xml.etree import ElementTree as ET
import json
import subprocess
import sys
import time, threading
import netconf
import pexpect
import math

def removeknowhost():
	print("remove /root/.ssh/known_hosts");
	subprocess.call(["rm", "-f", '/root/.ssh/known_hosts']);

def prettyXml(element, indent = '\t', newline = '\n', level = 0):
    if element:
        if element.text == None or element.text.isspace():
            element.text = newline + indent * (level + 1)    
        else:  
            element.text = newline + indent * (level + 1) + element.text.strip() + newline + indent * (level + 1)  
    temp = list(element)
    for subelement in temp:  
        if temp.index(subelement) < (len(temp) - 1):
            subelement.tail = newline + indent * (level + 1)  
        else:
            subelement.tail = newline + indent * level  
        prettyXml(subelement, indent, newline, level = level + 1)

def loadNetconf(xmlstr, device):
    print (xmlstr);

    #start the netconf request
    session = netconf.Session.connect(device, int('830'), str('root'))
    dstype = netconf.RUNNING
    status = session.editConfig(target=dstype, source=xmlstr, defop=netconf.NC_EDIT_DEFOP_REPLACE,
	erropt=netconf.NC_EDIT_ERROPT_NOTSET, testopt=netconf.NC_EDIT_TESTOPT_TESTSET)
    print('editconfig %s feedback: %s\n'%(dstype, status));
    getfeedback = session.getConfig(dstype);

    del(session);
    return (status, getfeedback);

#tsn config for tsn yang v2
def loadnetconfqbv(configdata):
    print(configdata);
    print(type(configdata));
    interfaces = ET.Element('interfaces');
    interfaces.set('xmlns', 'urn:ietf:params:xml:ns:yang:ietf-interfaces');
    interfaces.set('xmlns:sched', 'urn:ieee:std:802.1Q:yang:ieee802-dot1q-sched');
    interfaces.set('xmlns:preempt', 'urn:ieee:std:802.1Q:yang:ieee802-dot1q-preemption');

    port = ET.SubElement(interfaces, 'interface');
    iname = ET.SubElement(port, 'name');
    iname.text = configdata['port'];

    enable = ET.SubElement(port, 'enabled');
    enable.text = 'true';

    admin = ET.SubElement(port, 'sched:gate-parameters');
    gate_enable = ET.SubElement(admin, 'sched:gate-enabled');
    gate_enable.text = configdata['enable'];

    configchange = ET.SubElement(port, 'sched:config-change');
    configchange.text = 'true';

    #admin = ET.SubElement(port, 'admin');
    print(configdata['enable']);
    if (configdata['enable'] == 'false'):
        enable.text = 'false';
        prettyXml(interfaces);
        ET.dump(interfaces);
        qbvxmlb = ET.tostring(interfaces, encoding='utf8', method='xml');
        qbvxmlstr = str(qbvxmlb, encoding='utf-8');

        return loadNetconf(qbvxmlstr, configdata['device']);

    listlen = ET.SubElement(admin, 'sched:admin-control-list-length');
    listlen.text = str(len(configdata['entry']));

    for i in range(len(configdata['entry'])):
        gatelist = ET.SubElement(admin,'sched:admin-control-list');

        gindex = ET.SubElement(gatelist, 'sched:index');
        gindex.text = str(i);

        #gce = ET.SubElement(gatelist, 'gate-control-entry');
        oname = ET.SubElement(gatelist, 'sched:operation-name');
        oname.text = 'sched:set-gate-states';

        gentry = ET.SubElement(gatelist, 'sched:sgs-params');
        gatestate = ET.SubElement(gentry, 'sched:gate-states-value');
        gatestate.text = str(configdata['entry'][i]['gate']);
        ti = ET.SubElement(gentry, 'sched:time-interval-value');
        ti.text = str(configdata['entry'][i]['period']);

    #cycletime = ET.SubElement(admin, 'admin-cycle-time');
    #cycletime.text = '200000';
    if configdata.__contains__('basetime'):
        xs,zs=math.modf(float(configdata['basetime']));
        xsstr = str(xs).split('.');
        if (len(xsstr[1]) > 8):
            xshu = xsstr[1][0:9];
        else:
            xshu = xsstr[1].ljust(9, '0');
        basetime = ET.SubElement(admin, 'sched:admin-base-time');
        seconds = ET.SubElement(basetime, 'sched:seconds');
        seconds.text = str(int(zs));
        fragseconds = ET.SubElement(basetime, 'sched:fractional-seconds');
        fragseconds.text = xshu;

    prettyXml(interfaces);
    #ET.dump(tsn);
    qbvxmlb = ET.tostring(interfaces, encoding='utf8', method='xml');

    qbvxmlstr = str(qbvxmlb, encoding='utf-8');

    return loadNetconf(qbvxmlstr, configdata['device']);

def loadnetconfqbu(configdata):
    print(configdata);
    interfaces = ET.Element('interfaces');
    interfaces.set('xmlns', 'urn:ietf:params:xml:ns:yang:ietf-interfaces');
    interfaces.set('xmlns:preempt', 'urn:ieee:std:802.1Q:yang:ieee802-dot1q-preemption');
    port = ET.SubElement(interfaces, 'interface');
    iname = ET.SubElement(port, 'name');
    iname.text = configdata['port'];
    enable = ET.SubElement(port, 'enabled');
    enable.text =  configdata['enable'];
    tclist = ET.SubElement(port, 'preempt:frame-preemption-parameters');

    for i in range(len(configdata['plist'])):
        onetc = ET.SubElement(tclist, 'preempt:frame-preemption-status-table');
        index = ET.SubElement(onetc, 'preempt:traffic-class');
        index.text = str(configdata['plist'][i]['tc']);
        preemptable = ET.SubElement(onetc, 'preempt:frame-preemption-status');
        preemptable.text = configdata['plist'][i]['preemptable'];

    prettyXml(interfaces);
    #ET.dump(interfaces);
    qbuxmlb = ET.tostring(interfaces, encoding='utf8', method='xml');
    qbuxmlstr = str(qbuxmlb, encoding='utf-8');

    return loadNetconf(qbuxmlstr, configdata['device']);

def loadgetconfig(configdata):
    removeknowhost();
    session = netconf.Session.connect(configdata['device'], int('830'), str('root'))
    dstype = netconf.RUNNING;
    getfeedback = session.getConfig(dstype);

    del(session);
    return ('true', getfeedback);

app = Flask(__name__)
#app.config['SECRET_KEY'] = "dfdfdffdad"

#app.config.from_object('config')
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/configdeviceHTML')
def configdeviceHTML():
    deviceip = request.args.get('ip');
    #ret = devauthorize(deviceip);
    removeknowhost();
    return render_template('indexdevice.html')

@app.route('/configQbvHTML')
def configQbvHTML():
    return render_template('configQbv.html')

#need to add methods = ['POST']
@app.route('/qbvset',  methods=['POST'])
def qbvset():
    try:
       tojson = request.get_json();
       print (tojson);
       print("%s "%(tojson['device']));
       print (type(tojson))
       status, ret = loadnetconfqbv(tojson);
       print (ret);
    except Exception:
       status = 'false';
       return jsonify({"status": status, "getconfig": ''});
       raise exceptions.WrongParametersException
    return jsonify({"status": status, "getconfig":str(ret)});

@app.route('/qbuset',  methods=['POST'])
def qbuset():
    try:
       tojson = request.get_json();
       status, ret = loadnetconfqbu(tojson);
       print (ret);
    except Exception:
       status = 'false';
       return jsonify({"status": status, "getconfig": ''});
       raise exceptions.WrongParametersException
    return jsonify({"status": status, "getconfig":str(ret)});

@app.route('/getconfig',  methods=['POST'])
def getconfig():
    try:
       tojson = request.get_json();
       print (tojson);
       status, ret = loadgetconfig(tojson);
       print (ret);
    except Exception:
       status = 'false';
       return jsonify({"status": status, "getconfig": ''});
       raise exceptions.WrongParametersException
    return jsonify({"status": status, "getconfig":str(ret)});

@app.route('/configQciHTML')
def configQciHTML():
    return render_template('configQci.html')

@app.route('/configQbuHTML')
def configQbuHTML():
    return render_template('configQbu.html')

@app.route('/configQavHTML')
def configQavHTML():
    return render_template('configQav.html')

@app.route('/configp8021cbHTML')
def configp8021cbHTML():
    return render_template('configp8021cb.html')

devices = {}

def probe_boards(n):
	global devices
	while 1 :
	  devices_temp = {}
	  output = subprocess.Popen('avahi-browse -a -d local -t | grep OpenIL', \
				    shell = True, stdout =subprocess.PIPE, stderr=subprocess.STDOUT)

	  i = 0
	  for line in iter(output.stdout.readline, b''):
	     line_txt = line.decode("utf-8")
	     devices_list = line_txt.split()
	     if (devices_list[4] != 'SSH') and (devices_list[4] != 'ssh._tcp') :
		     continue
	     board = '%s.local'%(devices_list[3])
	     result = subprocess.Popen('avahi-resolve-host-name %s' %(board), \
				     shell = True, stdout =subprocess.PIPE, stderr=subprocess.STDOUT)

	     resultb = result.stdout.readline()
	     resulte_txt = resultb.decode("utf-8")
	     resulte_list = resulte_txt.split()
	     if (resulte_list[0] == 'Failed') :
	         continue
	     if (devices_temp.__contains__(resulte_list[0])) :
	         continue
	     devices_temp[resulte_list[0]] = resulte_list[1]
	     i += 1
	  
	  mutex.acquire()
	  devices.clear()
	  j = 0
	  for key, value in devices_temp.items():
	      devices[j] = {'name': key, 'ip': value}
	      j += 1
	  mutex.release()
	  print (devices)
	  time.sleep(5)

@app.route('/getdevices')
def getdevices():
	global devices
	mutex.acquire()
	reply = jsonify(devices)
	mutex.release()
	return reply

try:
   t_probeboards = threading.Thread(target=probe_boards, args=(5,))
   t_probeboards.start()
except:
	print ("Error: start new threading")

mutex = threading.Lock()

if __name__ == '__main__':
    app.run(host = "0.0.0.0" , port = 8180, debug = True)

t_probeboards.join()

