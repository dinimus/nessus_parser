#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os, requests, argparse, time
from argparse import RawTextHelpFormatter
from _nessus_core import NESSUS
from _docx_core import WORDDOCX
from _nessus_vulns import *

requests.packages.urllib3.disable_warnings()

## PARSING ARGS
parser = argparse.ArgumentParser(description="\033[1mNessus report parser\033[0m", formatter_class=RawTextHelpFormatter, epilog="\033[1mExample:\033[0m ./script.py -i report.nessus -o output.docx")
parser.add_argument('-i', '--input', metavar='report.nessus', type=str, help="Input nessus file")
parser.add_argument('-o', '--output', metavar='output.docx', type=str, help="Output report file")
parser.add_argument('-t', '--template', metavar='template.docx', type=str, default='_template_nessus.docx', help="Template of report file")
args = parser.parse_args()
## END ARGS

## GLOBAL VARS
nessus_filename = args.input
report_filename = args.output
template_filename = args.template

if nessus_filename == '':
	print("Input nessus report filename can not be empty")
	exit()
if report_filename == '':
	print("Output docx report filename can not be empty")
	exit()

with open(nessus_filename, 'r') as f:
	nessus_xml_content = f.read()

id_ssl_weak = ['26928', '78479', '58751', '81606', '94437', '89058', '69551']
id_ssl_wrong = ['45411', '15901', '124410']
id_cisco_ikev1_benigncertain = ['93736', '96802']
id_cisco_ios_vulns = ['']
id_esxi_vulns = ['123518', '118885', '111759']
docx = WORDDOCX(template_filename)
## END VARS

def group_vulns(group_type, plugID, vulns, vulns_rus):
	if not group_type in vulns.keys():
		if 'cve' in vulns[plugID]:
			cve = vulns[plugID]['cve']
		else:
			cve = ''
		if cve != '':
			vulns_rus[group_type]['cve'] = cve
		vulns_rus[group_type]['target'] = vulns[plugID]['target']
		vulns[group_type] = vulns_rus[group_type]
		del vulns[plugID]
	else:
		vulns[group_type]['target'].extend(vulns[plugID]['target'])
		if 'cve' in vulns[plugID]:
			cve = vulns[plugID]['cve']
		else:
			cve = ''
		if 'cve' in vulns[group_type] and cve != '':
			vulns[group_type]['cve'].extend(vulns[plugID]['cve'])
		elif not 'cve' in vulns[group_type] and cve != '':
			vulns[group_type]['cve'] = cve
		del vulns[plugID]
	return vulns

def main():
	print("(*) Nessus file processing")
	nessus = NESSUS(nessus_xml_content)
	print("(*) Nessus file parsing")
	# vulns_by_host_plug = nessus.parse_nessus_by_host_plug()
	vulns = nessus.parse_nessus_by_vuln()
	vulns_translated = vulns.copy()

	print('(*) Text translation')
	for plugID in vulns.keys():
		for rusplugID in vulns_rus:
			if plugID == rusplugID:
				vulns_translated[plugID]['pluginName'] = vulns_rus[rusplugID]['pluginName']
				vulns_translated[plugID]['description'] = vulns_rus[rusplugID]['description']
				vulns_translated[plugID]['solution'] = vulns_rus[rusplugID]['solution']
				if 'see_also' in vulns_rus[rusplugID]:
					vulns_translated[plugID]['see_also'] = vulns_rus[rusplugID]['see_also']
				if 'severity' in vulns_rus[rusplugID]:
					vulns_translated[plugID]['severity'] = vulns_rus[rusplugID]['severity']
				break
			if plugID in id_ssl_weak:
				vulns_translated = group_vulns('ssl_weak', plugID, vulns_translated, vulns_rus)
				break
			elif plugID in id_ssl_wrong:
				vulns_translated = group_vulns('ssl_wrong', plugID, vulns_translated, vulns_rus)
				break
			elif plugID in id_cisco_ikev1_benigncertain:
				vulns_translated = group_vulns('cisco_ikev1_benigncertain', plugID, vulns_translated, vulns_rus)
				break
			elif plugID in id_esxi_vulns:
				vulns_translated = group_vulns('esxi_vulns', plugID, vulns_translated, vulns_rus)
				break

	print("(*) Vulns sorting")
	sorted_rus_vulns = {}
	for i in sorted(vulns_translated, key=lambda i:vulns_translated[i]['severity'], reverse=True):
		sorted_rus_vulns[i] = vulns_translated[i]

	print('(*) Document creating')
	docx.create_nessus_docx(report_filename, sorted_rus_vulns)

if __name__ == "__main__" : main()
