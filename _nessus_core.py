#!/usr/bin/env python3
from lxml import etree
# based on the https://avleonov.com/2020/03/09/parsing-nessus-v2-xml-reports-with-python

class NESSUS(object):
	def __init__(self, xml_content):
		self.single_params = ["agent", "cvss3_base_score", "cvss3_temporal_score", "cvss3_temporal_vector", "cvss3_vector",
					 "cvss_base_score", "cvss_temporal_score", "cvss_temporal_vector", "cvss_vector", "description",
					 "exploit_available", "exploitability_ease", "exploited_by_nessus", "fname", "in_the_news",
					 "patch_publication_date", "plugin_modification_date", "plugin_name", "plugin_publication_date",
					 "plugin_type", "script_version", "see_also", "solution", "synopsis", "vuln_publication_date",
					 "compliance",
					 "{http://www.nessus.org/cm}compliance-check-id",
					 "{http://www.nessus.org/cm}compliance-check-name",
					 "{http://www.nessus.org/cm}audit-file",
					 "{http://www.nessus.org/cm}compliance-info",
					 "{http://www.nessus.org/cm}compliance-result",
					 "{http://www.nessus.org/cm}compliance-see-also"]
		bytes_xml = bytes(bytearray(xml_content, encoding='utf-8'))
		self.p = etree.XMLParser(huge_tree=True, ns_clean=True, recover=True)
		self.root = etree.fromstring(text=bytes_xml, parser=self.p)
	
	def parse_nessus_by_host_plug(self):
		vulnerabilities = dict()
		for block in self.root:
			if block.tag == "Report":
				for report_host in block:
					host_properties_dict = dict()
					for report_item in report_host:
						if report_item.tag == "HostProperties":
							for host_properties in report_item:
								host_properties_dict[host_properties.attrib['name']] = host_properties.text
					for report_item in report_host:
						if 'pluginName' in report_item.attrib:
							vulner_struct = dict()
							vulner_struct['port'] = report_item.attrib['port']
							vulner_struct['pluginName'] = report_item.attrib['pluginName']
							vulner_struct['pluginFamily'] = report_item.attrib['pluginFamily']
							vulner_struct['pluginID'] = report_item.attrib['pluginID']
							vulner_struct['svc_name'] = report_item.attrib['svc_name']
							vulner_struct['protocol'] = report_item.attrib['protocol']
							vulner_struct['severity'] = report_item.attrib['severity']
							for param in report_item:
								if param.tag == "risk_factor":
									risk_factor = param.text
									vulner_struct['host'] = report_host.attrib['name']
									vulner_struct['riskFactor'] = risk_factor
								elif param.tag == "plugin_output":
									if not "plugin_output" in vulner_struct:
										vulner_struct["plugin_output"] = list()
									if not param.text in vulner_struct["plugin_output"]:
										vulner_struct["plugin_output"].append(param.text)
								else:
									if not param.tag in self.single_params:
										if not param.tag in vulner_struct:
											vulner_struct[param.tag] = list()
										if not isinstance(vulner_struct[param.tag], list):
											vulner_struct[param.tag] = [vulner_struct[param.tag]]
										if not param.text in vulner_struct[param.tag]:
											vulner_struct[param.tag].append(param.text)
									else:
										vulner_struct[param.tag] = param.text
							for param in host_properties_dict:
								vulner_struct[param] = host_properties_dict[param]
							compliance_check_id = ""
							if 'compliance' in vulner_struct:
								if vulner_struct['compliance'] == 'true':
									compliance_check_id = vulner_struct['{http://www.nessus.org/cm}compliance-check-id']
							if compliance_check_id == "":
								vulner_id = "{0}|{1}|{2}|{3}".format(vulner_struct['host'], vulner_struct['port'], vulner_struct['protocol'], vulner_struct['pluginID'])
							else:
								vulner_id = "{0}|{1}|{2}|{3}|{4}".format(vulner_struct['host'], vulner_struct['port'], vulner_struct['protocol'], vulner_struct['pluginID'], compliance_check_id)
							if not vulner_id in vulnerabilities:
								vulnerabilities[vulner_id] = vulner_struct
		return vulnerabilities

	def parse_nessus_by_vuln(self):
		vulns = dict()
		for block in self.root:
			if block.tag == "Report":
				for report_host in block:
					# print(etree.tostring(report_host, pretty_print=True))
					host_properties_dict = dict()
					for report_item in report_host:
						if report_item.tag == "HostProperties":
							for host_properties in report_item:
								if host_properties.attrib['name'] == 'host-fqdn':
									host_properties_dict['host_fqdn'] = host_properties.text
								else:
									host_properties_dict[host_properties.attrib['name']] = host_properties.text
								# print('{}: {}'.format(host_properties.attrib['name'], host_properties.text))
						if 'pluginName' in report_item.attrib:
							vulner_struct = dict()
							vulner_struct['port'] = report_item.attrib['port']
							vulner_struct['pluginName'] = report_item.attrib['pluginName']
							vulner_struct['pluginFamily'] = report_item.attrib['pluginFamily']
							vulner_struct['pluginID'] = report_item.attrib['pluginID']
							vulner_struct['svc_name'] = report_item.attrib['svc_name']
							vulner_struct['protocol'] = report_item.attrib['protocol']
							vulner_struct['severity'] = report_item.attrib['severity']
							for param in report_item:
								if param.tag == "risk_factor":
									risk_factor = param.text
									vulner_struct['host'] = report_host.attrib['name']
									vulner_struct['riskFactor'] = risk_factor
								elif param.tag == "plugin_output":
									if not "plugin_output" in vulner_struct:
										vulner_struct["plugin_output"] = list()
									if not param.text in vulner_struct["plugin_output"]:
										vulner_struct["plugin_output"].append(param.text)
								else:
									if not param.tag in self.single_params:
										if not param.tag in vulner_struct:
											vulner_struct[param.tag] = list()
										if not isinstance(vulner_struct[param.tag], list):
											vulner_struct[param.tag] = [vulner_struct[param.tag]]
										if not param.text in vulner_struct[param.tag]:
											vulner_struct[param.tag].append(param.text)
									else:
										vulner_struct[param.tag] = param.text
							for param in host_properties_dict:
								vulner_struct[param] = host_properties_dict[param]
							compliance_check_id = ""
							if 'compliance' in vulner_struct:
								if vulner_struct['compliance'] == 'true':
									compliance_check_id = vulner_struct['{http://www.nessus.org/cm}compliance-check-id']

							host = vulner_struct['host']
							port = vulner_struct['port']
							protocol = vulner_struct['protocol']
							if vulner_struct['pluginID'] not in vulns:
								if 'host_fqdn' in vulner_struct:
									host_fqdn = vulner_struct['host_fqdn']
									vulner_struct['host_fqdn'] = [host_fqdn]
								else:
									vulner_struct['host_fqdn'] = []
								if 'plugin_output' in vulner_struct:
									plugin_output = vulner_struct['plugin_output']
									vulner_struct['plugin_output'] = [plugin_output]
								else:
									vulner_struct['plugin_output'] = []
								if port == '0':
									target = host
								else:
									target = '{0}:{1}/{2}'.format(host, port, protocol)
								vulner_struct['host'], vulner_struct['port'], vulner_struct['protocol'] = [host], [port], [protocol]
								vulner_struct['target'] = [target]
								vulns[vulner_struct['pluginID']] = vulner_struct
							else:
								vulns[vulner_struct['pluginID']]['host'].append(host)
								vulns[vulner_struct['pluginID']]['port'].append(port)
								vulns[vulner_struct['pluginID']]['protocol'].append(protocol)
								if port == '0':
									target = host
								else:
									target = '{0}:{1}/{2}'.format(host, port, protocol)
								vulns[vulner_struct['pluginID']]['target'].append(target)
								if 'host_fqdn' in vulner_struct:
									vulns[vulner_struct['pluginID']]['host_fqdn'].append(vulner_struct['host_fqdn'])
								if 'plugin_output' in vulner_struct:
									vulns[vulner_struct['pluginID']]['plugin_output'].append(vulner_struct['plugin_output'])
		return vulns
