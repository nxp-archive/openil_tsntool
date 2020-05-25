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
    removeknowhost();
    #start the netconf request
    session = netconf.Session.connect(device, int('830'), str('root'))
    dstype = netconf.RUNNING
    status = session.editConfig(target=dstype, source=xmlstr, defop=netconf.NC_EDIT_DEFOP_MERGE,
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
    interfaces.set('xmlns:ianaift', 'urn:ietf:params:xml:ns:yang:iana-if-type');

    port = ET.SubElement(interfaces, 'interface');
    iname = ET.SubElement(port, 'name');
    iname.text = configdata['port'];

    enable = ET.SubElement(port, 'enabled');
    enable.text = 'true';

    itype = ET.SubElement(port, 'type');
    itype.text = 'ianaift:ethernetCsmacd';

    admin = ET.SubElement(port, 'sched:gate-parameters');
    gate_enable = ET.SubElement(admin, 'sched:gate-enabled');
    gate_enable.text = configdata['enable'];

    configchange = ET.SubElement(admin, 'sched:config-change');
    configchange.text = 'true';

    #admin = ET.SubElement(port, 'admin');
    print(configdata['enable']);
    if (configdata['enable'] == 'false'):
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
    interfaces.set('xmlns:ianaift', 'urn:ietf:params:xml:ns:yang:iana-if-type');
    port = ET.SubElement(interfaces, 'interface');
    iname = ET.SubElement(port, 'name');
    iname.text = configdata['port'];
    enable = ET.SubElement(port, 'enabled');
    enable.text =  'true';

    itype = ET.SubElement(port, 'type');
    itype.text = 'ianaift:ethernetCsmacd';

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

def loadncqcisid(configdata):
    print(configdata);
    bridges = ET.Element('bridges');
    bridges.set('xmlns', 'urn:ieee:std:802.1Q:yang:ieee802-dot1q-bridge');
    bridges.set('xmlns:stream', 'urn:ieee:std:802.1Q:yang:ieee802-dot1q-stream-id');
    bridge = ET.SubElement(bridges, 'bridge');
    #we have to judge by port name
    brname = ET.SubElement(bridge, 'name');
    brtype = ET.SubElement(bridge, 'bridge-type');
    address = ET.SubElement(bridge, 'address');

    if (configdata['port'].find("eno") >= 0):
        brname.text = 'enetc';
        address.text = '00-00-00-00-00-01';
    else:
        brname.text = 'switch';
        address.text = '00-00-00-00-00-02';

    brtype.text = 'provider-edge-bridge';
    component = ET.SubElement(bridge, 'component');
    compname = ET.SubElement(component, 'name');
    compname.text = configdata['port'];

    comptype = ET.SubElement(component, 'type');
    comptype.text = 'edge-relay-component';
    streams = ET.SubElement(component, 'stream:streams');
    sidtable = ET.SubElement(streams, 'stream:stream-identity-table');
    index = ET.SubElement(sidtable, 'stream:index');
    index.text = configdata['index'];

    enable = ET.SubElement(sidtable, 'stream:stream-id-enabled');
    enable.text = configdata['enable'];
    if (configdata['enable'] == 'false'):
        prettyXml(bridges);
        sidxmlb = ET.tostring(bridges, encoding='utf8', method='xml');
        sidxmlstr = str(sidxmlb, encoding='utf-8');
        return loadNetconf(sidxmlstr, configdata['device']);

    streamhandle = ET.SubElement(sidtable, 'stream:stream-handle');
    streamhandle.text = configdata['streamhandle'];
    identype = ET.SubElement(sidtable, 'stream:identification-type');
    identype.text =  configdata['filtertype'];
    param = ET.SubElement(sidtable, 'stream:parameters');
    if (configdata['filtertype'] == 'null'):
        nullpara = ET.SubElement(param, 'stream:null-stream-identification-params');
        destaddr = ET.SubElement(nullpara, 'stream:dest-address');
        destaddr.text = configdata['macaddr'];
        vlantype = ET.SubElement(nullpara, 'stream:vlan-tagged');
        vlantype.text = configdata['vlantype'];
        if ('vlanid' in configdata):
             vlanid = ET.SubElement(nullpara, 'stream:vlan-id');
             vlanid.text = configdata['vlanid'];
    elif (configdata['filtertype'] == "source-mac-and-vlan"):
        srcpara = ET.SubElement(param, 'stream:source-mac-and-vlan-identification-params');
        destaddr = ET.SubElement(nullpara, 'stream:source-address');
        destaddr.text = configdata['macaddr'];
        vlantype = ET.SubElement(nullpara, 'stream:vlan-tagged');
        vlantype.text = configdata['vlantype'];
        if ('vlanid' in configdata):
             vlanid = ET.SubElement(nullpara, 'stream:vlan-id');
             vlanid.text = configdata['vlanid'];
    else:
        print("filter type not supported");
        return ('false', "filter type not supported");

    prettyXml(bridges);
    #ET.dump(bridges);
    sidxmlb = ET.tostring(bridges, encoding='utf8', method='xml');
    sidxmlstr = str(sidxmlb, encoding='utf-8');

    return loadNetconf(sidxmlstr, configdata['device']);

def createsfixml(component, configdata):
    streamfilter = ET.SubElement(component, 'sfsg:stream-filters');
    sfitable = ET.SubElement(streamfilter, 'sfsg:stream-filter-instance-table');
    index = ET.SubElement(sfitable, 'sfsg:stream-filter-instance-id');
    index.text = configdata['index'];
    enable = ET.SubElement(sfitable, 'qci-augment:stream-filter-enabled');
    enable.text = configdata['enable'];
    if (configdata['enable'] == 'false'):
        return

    if (configdata.__contains__('streamhandle')):
        streamhandle = ET.SubElement(sfitable, 'sfsg:stream-handle');
        streamhandle.text = configdata['streamhandle'];
    else:
        streamhandle = ET.SubElement(sfitable, 'sfsg:wildcard');

    prio = ('zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven');
    priority = ET.SubElement(sfitable, 'sfsg:priority-spec');
    if (configdata.__contains__('priority')):
        priority.text = prio[int(configdata['priority'])];
    else:
        priority.text = 'wildcard';

    gateid = ET.SubElement(sfitable, 'sfsg:stream-gate-ref');
    gateid.text = configdata['gateid'];

    filterspec = ET.SubElement(sfitable, 'sfsg:filter-specification-list');
    findex = ET.SubElement(filterspec, 'sfsg:index');
    findex.text = '0';

    if (configdata.__contains__('flowmeterid')):
        fmiid = ET.SubElement(filterspec, 'psfp:flow-meter-ref');
        fmiid.text = configdata['flowmeterid'];

def createsgixml(component, configdata):
    streamgate = ET.SubElement(component, 'sfsg:stream-gates');
    sgitable =  ET.SubElement(streamgate, 'sfsg:stream-gate-instance-table');
    index = ET.SubElement(sgitable, 'sfsg:stream-gate-instance-id');
    index.text = configdata['index'];
    gateen = ET.SubElement(sgitable, 'sfsg:gate-enable');
    gateen.text = configdata['enable'];
    if (configdata['enable'] == 'false'):
        return;

    prio = ('zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven');

    initgate = ET.SubElement(sgitable, 'sfsg:admin-gate-states');
    initgate.text = configdata['initgate'];
    initipv = ET.SubElement(sgitable, 'sfsg:admin-ipv');
    intinitipv = int(configdata['initipv']);
    if (intinitipv >= 0 and intinitipv < 8) :
        initipv.text = prio[intinitipv];
    else :
        initipv.text = 'wildcard';

    listlength =ET.SubElement(sgitable, 'psfp:admin-control-list-length');
    listlength.text = str(len(configdata['entry']));
    for i in range(len(configdata['entry'])):
        adminlist = ET.SubElement(sgitable, 'psfp:admin-control-list');
        entryindex = ET.SubElement(adminlist, 'psfp:index');
        entryindex.text = str(i);
        ename = ET.SubElement(adminlist, 'psfp:operation-name');
        ename.text = 'psfp:set-gate-and-ipv';
        cyclepara = ET.SubElement(adminlist, 'psfp:parameters');
        egate = ET.SubElement(cyclepara, 'psfp:gate-state-value');
        egate.text = configdata['entry'][i]['gate'];
        eti = ET.SubElement(cyclepara, 'psfp:time-interval-value');
        eti.text = configdata['entry'][i]['period'];
        einitipv = ET.SubElement(cyclepara, 'psfp:ipv-value');
        eintinitipv = int(configdata['entry'][i]['ipv']);
        if (eintinitipv >= 0 and eintinitipv < 8) :
            einitipv.text = prio[eintinitipv];
        else:
            einitipv.text = 'wildcard';

    if configdata.__contains__('basetime'):
        xs,zs=math.modf(float(configdata['basetime']));
        xsstr = str(xs).split('.');
        if (len(xsstr[1]) > 8):
            xshu = xsstr[1][0:9];
        else:
            xshu = xsstr[1].ljust(9, '0');
        basetime = ET.SubElement(sgitable, 'psfp:admin-base-time');
        seconds = ET.SubElement(basetime, 'psfp:seconds');
        seconds.text = str(int(zs));
        fragseconds = ET.SubElement(basetime, 'psfp:nanoseconds');
        fragseconds.text = xshu;

def createfmixml(component, configdata):
    flowmeter= ET.SubElement(component, 'psfp:flow-meters');
    fmitable =  ET.SubElement(flowmeter, 'psfp:flow-meter-instance-table');
    index = ET.SubElement(fmitable, 'psfp:flow-meter-instance-id');
    index.text = configdata['index'];
    enable = ET.SubElement(fmitable, 'qci-augment:flow-meter-enabled');
    enable.text = configdata['enable'];
    if (configdata['enable'] == 'false'):
        return;

    if configdata.__contains__('cir'):
        cir = ET.SubElement(fmitable, 'psfp:committed-information-rate');
        cir.text = configdata['cir'];
    if configdata.__contains__('cbs'):
        cbs = ET.SubElement(fmitable, 'psfp:committed-burst-size');
        cbs.text = configdata['cbs'];
    if configdata.__contains__('eir'):
        eir = ET.SubElement(fmitable, 'psfp:excess-information-rate');
        eir.text = configdata['eir'];
    if configdata.__contains__('ebs'):
        ebs = ET.SubElement(fmitable, 'psfp:excess-burst-size');
        ebs.text = configdata['ebs'];

    cf = ET.SubElement(fmitable, 'psfp:coupling-flag');
    if (configdata['cf'] == True):
        cf.text = 'one';
    else:
        cf.text = 'zero';

    cm = ET.SubElement(fmitable, 'psfp:color-mode');
    if (configdata['cm'] == True):
        cm.text = 'color-blind';
    else:
        cm.text = 'color-aware';

    dropyellow = ET.SubElement(fmitable, 'psfp:drop-on-yellow');
    if (configdata['dropyellow'] == True):
        dropyellow.text = 'true';
    else:
        dropyellow.text = 'false';

def loadncqciset(configdata):
    print(configdata);
    bridges = ET.Element('bridges');
    bridges.set('xmlns', 'urn:ieee:std:802.1Q:yang:ieee802-dot1q-bridge');
    bridges.set('xmlns:sfsg', 'urn:ieee:std:802.1Q:yang:ieee802-dot1q-stream-filters-gates');
    bridges.set('xmlns:psfp', 'urn:ieee:std:802.1Q:yang:ieee802-dot1q-psfp');
    bridges.set('xmlns:qci-augment', 'urn:ieee:std:802.1Q:yang:ieee802-dot1q-qci-augment');

    bridge = ET.SubElement(bridges, 'bridge');
    #we have to judge by port name
    brname = ET.SubElement(bridge, 'name');
    address = ET.SubElement(bridge, 'address');
    brtype = ET.SubElement(bridge, 'bridge-type');

    if (configdata['port'].find("eno") >= 0):
        brname.text = 'enetc';
        address.text = '00-00-00-00-00-01';
    else:
        brname.text = 'switch';
        address.text = '00-00-00-00-00-02';

    brtype.text = 'provider-edge-bridge';
    component = ET.SubElement(bridge, 'component');
    compname = ET.SubElement(component, 'name');
    compname.text = configdata['port'];

    comptype = ET.SubElement(component, 'type');
    comptype.text = 'edge-relay-component';

    if (configdata['whichpart'] == 'sfi'):
        createsfixml(component, configdata);
    elif (configdata['whichpart'] == 'sgi'):
        createsgixml(component, configdata);
    elif (configdata['whichpart'] == 'fmi'):
        createfmixml(component, configdata);
    else:
         print("No this config: %s"%(configdata['whichpart']));

    prettyXml(bridges);
    qcixmlb = ET.tostring(bridges, encoding='utf8', method='xml');
    qcixmlstr = str(qcixmlb, encoding='utf-8');

    return loadNetconf(qcixmlstr, configdata['device']);

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
    #removeknowhost();
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

@app.route('/qcisidset', methods=['POST'])
def qcisidset():
    try:
        tojson = request.get_json();
        status, ret = loadncqcisid(tojson);
        print(ret);
    except Exception:
       status = 'false';
       return jsonify({"status": status, "getconfig": ''});
       raise exceptions.WrongParametersException
    return jsonify({"status": status, "getconfig":str(ret)});

@app.route('/qciset', methods=['POST'])
def qciset():
    try:
        tojson = request.get_json();
        status, ret = loadncqciset(tojson);
        print(ret);
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

