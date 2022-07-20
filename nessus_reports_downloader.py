#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os, requests, time, json

requests.packages.urllib3.disable_warnings()

base = 'https://IP_of_NESSUS:8834'
accessKey = 'YOUR_access_KEY'
secretKey = 'YOUR_secret_KEY'

headers = {
	"Content-Type": "application/json",
	"X-ApiKeys": "accessKey={0}; secretKey={1};".format(accessKey, secretKey)
}

scans = requests.get('{0}/scans'.format(base), headers = headers, verify=False).json()

scanlist = {}
data_exp = json.dumps({"format":"nessus"})

for scan in scans['scans']:
	try:
		exp_file = requests.post('{0}/scans/{1}/export'.format(base, str(scan['id'])), data=data_exp, headers = headers, verify=False).json()
		scanlist[scan['id']] = exp_file['file']
	except:
		continue

for scan_id in scanlist:
	url = '{0}/scans/{1}/export/{2}/download'.format(base, scan_id, scanlist[scan_id])
	filecontent = requests.get(url, headers = headers, verify=False).text
	filename = 'report_{0}.nessus'.format(scan_id)
	print(filename)
	with open(filename,"w") as out_file:
		out_file.write(filecontent)
