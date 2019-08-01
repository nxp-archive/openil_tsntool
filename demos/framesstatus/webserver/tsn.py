#!/usr/bin/python3
#
#Copyright 2019 NXP
#

from flask import Flask, render_template, request
from flask import jsonify
import json
import subprocess

app = Flask(__name__)
app.config['SECRET_KEY'] = "dfdfdffdad"

app.config.from_object('config')

interface= app.config["CONFIGPORT"]

@app.route('/')
def index():
    return render_template('fcap.html')

@app.route('/qbvenable')
def qbvenable():
	output = subprocess.Popen('tsntool qbvset --device %s --entryfile qbv1.txt --basetime 100000000' %(interface), \
				  shell = True, stdout =subprocess.PIPE, stderr=subprocess.STDOUT)
	return output.stdout.read()

@app.route('/qbvdisable')
def qbvdisable():
	output = subprocess.Popen('tsntool qbvset --device %s --disable' %(interface), \
				  shell = True, stdout =subprocess.PIPE, stderr=subprocess.STDOUT)
	return output.stdout.read()

@app.route('/qcienable')
def qcienable():
	output = subprocess.Popen('tsntool qcisfiset --device %s --index 2 --gateid 2' %(interface), \
				  shell = True, stdout =subprocess.PIPE, stderr=subprocess.STDOUT)
	output = subprocess.Popen('tsntool qcisgiset --device %s --index 2 --initgate 1 --gatelistfile sgi1.txt' %(interface), \
				  shell = True, stdout =subprocess.PIPE, stderr=subprocess.STDOUT)

	return output.stdout.read()

@app.route('/qcidisable')
def qcidisable():
	output = subprocess.Popen('tsntool qcisfiset --device %s --index 2 --disable' %(interface), \
				  shell = True, stdout =subprocess.PIPE, stderr=subprocess.STDOUT)
	output = subprocess.Popen('tsntool qcisgiset --device %s --index 2 --disable' %(interface), \
				  shell = True, stdout =subprocess.PIPE, stderr=subprocess.STDOUT)

	return output.stdout.read()

@app.route('/clientpostdata', methods=['POST'])
def clientpostdata():
	if request.method == 'POST':
		a = request.form['mydata']
	print(a)
	d = {'name': 'xmr', 'age': 18}
	return jsonify(d)

if __name__ == '__main__':
    app.run(host = "0.0.0.0" , port = 8180, debug = True)
