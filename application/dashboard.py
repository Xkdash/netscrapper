from flask import Blueprint,render_template,request,redirect,url_for
import json
import validators
import ipaddress
from urllib.parse import urlparse
import requests
from PIL import Image
import time
import warnings
from datetime import datetime
from dateutil import relativedelta
import numpy as np
import socket
from urllib.request import Request, urlopen
from bs4 import BeautifulSoup
import html5lib
from datetime import datetime as dt
import urllib.parse

dash_bp=Blueprint('dash_bp', __name__,template_folder='templates',static_folder='static')
@dash_bp.route("/",methods=['GET', 'POST'])
@dash_bp.route("/dashboard",methods=['GET', 'POST'])
def dash_index():
	detailed=json.load(open("application/logs/detailed_news.json"))
	cve_list=json.load(open("application/logs/cve_news.json"))
	eve=json.load(open("application/logs/events.json"))
	keywords=json.load(open("application/logs/keywords.json"))
	sources=["All"]
	chosen=detailed
	src_selected=0
	cve_hits=[]
	
	for item in cve_list:
		if "," in item['cve']:
			cve_list.remove(item)

	for item in keywords:
		for c in cve_list:
			if item in c['vuln_name'].lower() and float(c['cvss']) > 7.0:
				cve_hits.append({'affected':item, 'cve':c['cve']})

	for item in detailed:
		if "source" in list(item.keys()):
			if item['source'] not in sources:
				sources.append(item['source'])
	

	if request.method=="POST":
		src_select=request.form.get("source_select","")

		if src_select!="":
			if int(src_select)==0:
				chosen=detailed
			elif int(src_select)>0 and int(src_select)<=len(detailed)+1:
				key=sources[int(src_select)]
				chosen=[]
				for item in detailed:
					if item['source']==key:
						chosen.append(item)
			src_selected=int(src_select)
	return render_template("index.html",cve_data=cve_list,detailed=chosen,srcs=sources,src_selected=src_selected,upcoming=eve[0],cve_hits=cve_hits)

def defangURL(url):
    url=url.replace(":","[:]")
    url=url.replace(".","[.]")
    return url

def VT_URLsubmit(url):
    api_key="6f182fa8c22759f53b7321acf70ed324685c4e3ecb16db60adb798ac3d02c0ff"
    base_url = "https://www.virustotal.com/vtapi/v2/url/scan"
    params = {"apikey": api_key, "url" : url}
    response = requests.post(base_url, data=params, verify=False).json()
    if response['scan_id'] != "":
        return response['resource']
    else:
        return -1

def URLSCANIO_submit(url):
    api_key="10027661-63ef-43e6-919b-d424fb9671e8"
    base_url='https://urlscan.io/api/v1/scan/'
    headers = {'API-Key':api_key,'Content-Type':'application/json'}
    data = {"url": url, "visibility": "public"}
    response = requests.post(base_url,headers=headers, data=json.dumps(data), verify=False)
    if response.status_code==200:
        return response.json()
    else: 
        return -1
def VT_URLverdict(res_dict):
    scans=res_dict["scans"]
    keys=list(scans.keys())
    mal_list=[]
    for i in range(len(keys)):
        if scans[keys[i]]['detected']==True:
            if scans[keys[i]]['result'] in mal_list:
                continue
            else:
                mal_list.append(scans[keys[i]]['result'])
    uniq=""
    for i in range(len(mal_list)):
        item=mal_list[i].split(" ")[0].title()
        uniq=uniq+item+"/"
        
    uniq=uniq[:-1]+" site"
    return uniq

def VT_URLfetch(url):
    api_key="6f182fa8c22759f53b7321acf70ed324685c4e3ecb16db60adb798ac3d02c0ff"
    base_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key,'resource':url}
    response = requests.get(base_url, params=params, verify=False).json()
    positives=response['positives']
    #print(response)
    total=response['total']
    score="("+str(positives)+"/"+str(total)+") Detections are Positive"
    verdict=""
    if positives == 0:
        verdict="Clean"
        color="text-success"
    else:
        color="text-danger"
        verdict_str=VT_URLverdict(response)
        if verdict_str=="":
            verdict="Suspicious/Malicious"
        else:
            verdict = verdict_str
    base_link="https://www.virustotal.com/gui/url/"
    uniqueid=response['scan_id'].split("-")[0]
    ref_link=base_link
    if uniqueid !="":
        ref_link+=uniqueid
    return score,verdict,ref_link,color

def URLSCAN_fetch(urlscan_res):
    base_url="https://urlscan.io/api/v1/result/"
    uuid=urlscan_res['uuid']
    results=requests.get(base_url+uuid, verify=False).json()
    print("Urlscan.io link: "+ urlscan_res['result'])
    #print(results)
    return results

def URLSCAN_verdict(res_dict):
	if "verdicts" in list(res_dict.keys()):
		ver=res_dict['verdicts']
		uniq=""
		brand="Unknown"
		if ver['overall']['malicious'] == True:

			for i in range(len(ver['overall']['categories'])):
			    item=ver['overall']['categories'][i].title()
			    uniq=uniq+item+"/"
			uniq=uniq[:-1]+" site"
			if len(ver['overall']['brands']) >=1:
			    brand=ver['urlscan']['brands'][0]['name']
		else:
		    uniq="No Classification"
		ipinfo=[]
		page=list(res_dict['page'].keys())
		if 'domain' in page:
			ipinfo.append("Domain: "+res_dict['page']['domain'])
		if 'country' in page:
			ipinfo.append("Country: "+res_dict['page']['country'])
		if 'country' in page:
			ipinfo.append("City: "+res_dict['page']['city'])
		if 'country' in page:
			ipinfo.append("IP: "+res_dict['page']['ip'])
		print(uniq, brand, ipinfo)
		return uniq, brand, ipinfo
	return "No Result","Unknown",["Unknown"]
def VT_IPfetch(ip):
    api_key="6f182fa8c22759f53b7321acf70ed324685c4e3ecb16db60adb798ac3d02c0ff"
    base_url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {"apikey": api_key, "ip" : ip}
    response = requests.get(base_url, params=params, verify=False).json()
    return response

def AbuseIPDB_ReportsLookup(ip):
	warnings.filterwarnings('ignore')
	api_key="96c956493eebf5eb40bca6885a0438421278c01af6a557c4c1734888298cfdf45131f2ababf6f38f"
	base_url = "https://api.abuseipdb.com/api/v2/check"
	headers={"Key": api_key}
	params = {"ipAddress" : ip}
	response = requests.get(base_url, headers=headers, params=params, verify=False)
	print(response.status_code)
	if response.status_code==200:
		data=response.json()
		if "data" in list(data.keys()):
		    return data['data']
		else:
		    return -1
def VT_hash(text):
    warnings.filterwarnings('ignore')
    url = "https://www.virustotal.com/api/v3/files/"+text
    headers = {
        "accept": "application/json",
        "x-apikey": "6f182fa8c22759f53b7321acf70ed324685c4e3ecb16db60adb798ac3d02c0ff"
    }
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code==200:
        stats=response.json()['data']['attributes']['last_analysis_stats']
        mal=0
        und=0
        info=[]
        #print(response.json()['data']['attributes']["type_description"])
        if "type_description" in list(response.json()['data']['attributes'].keys()):
        	info.append("Threat Type: "+response.json()['data']['attributes']["type_description"])
        	print(info)
        if "popular_threat_classification" in list(response.json()['data']['attributes'].keys()):
        	if "suggested_threat_label" in list(response.json()['data']['attributes']["popular_threat_classification"].keys()):
        		info.append("Threat Label: "+response.json()['data']['attributes']["popular_threat_classification"]["suggested_threat_label"])
        		print(info)
        info.append("ViruTotal Link: https://www.virustotal.com/gui/file/"+text)
        if "malicious" in list(stats.keys()):
            mal=int(stats['malicious'])
        if "undetected" in list(stats.keys()):
            und=int(stats['malicious'])
        if mal==0:
            return ["Clean"], "text-success",info
        else:
            return ["Malicious Score: ("+str(mal)+"/"+str(mal+und)+")"],"text-danger",info
    else:
        return ["No Results Found"], "text-primary",info

def URLSCAN_screenshot(uuid):
    url="https://urlscan.io/screenshots/"
    snap=Image.open(requests.get(url+uuid+".png", stream=True, verify=False).raw)
    return snap

def cveSearch(cvename):
    URL = "https://nvd.nist.gov/vuln/detail/"+cvename
    req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    webpage=urlopen(req).read()
    page_soup=BeautifulSoup(webpage,'html.parser')
    #print(page_soup.prettify())
    vuln_desc=page_soup.find_all('p',{'data-testid':'vuln-description'})[0].text.strip()
    #print(vuln_desc)
    #cvss_ver=page_soup.find_all('div',{'data-testid':'vuln-cvss3-panel'})[0].find_all('strong')[0].text.strip()[:-1]
    cvss_val=page_soup.find_all('a',{'data-testid':'vuln-cvss3-cna-panel-score'})[0].text.strip().split(" ")
    cvss_score=cvss_val[0].strip()
    cvss_sev=cvss_val[1].strip()
    #print(cvss_score)
    sev_vec=page_soup.find_all('span',{'class':'tooltipCvss3CnaMetrics'})[0].text.strip()[9:]
    cvss_ver=page_soup.find_all('span',{'class':'tooltipCvss3CnaMetrics'})[0].text.strip()[:8]
    vec_temp=sev_vec.split("/")
    vectors=[]
    met={'AV':'Attack Vector','AC':'Attack Complexity','PR':'Privileges Required','UI':'User Interaction','S':'Scope','C': 'Confidentiality','I':'Integrity','A':'Availability'}
    val={'AV':{'L':'Local','A':'Adjacent Network','N':'Network','P':'Physical'},'AC':{'H':'High','M':'Medium','L':'Low'},'AU':{'M':'Multiple','S':'Single','N':'None'},'C':{'N':'None','P':'Partial','C':'Complete'},'I':{'N':'None','P':'Partial','C':'Complete'}, 'A':{'N':'None','P':'Partial','C':'Complete'},'UI':{'N':'None','R':'Required'},'PR':{'N':'None','L':'Low','H':'High'},'S':{'U':'Unchanged','C':'Changed'}}
    for vec in vec_temp:
        vc=vec.strip().split(":")
        V=vc[0].strip()
        N=vc[1].strip()
        if V in list(met.keys()) and V in list(val.keys()):
            if N in list(val[V].keys()):
                vectors.append({met[V] : val[V][N]})
    #print(vectors)

    vuln_hyp_table=page_soup.find_all('table',{'data-testid':'vuln-hyperlinks-table'})[0].find_all('td')
    resources=[]
    links=[]
    res_val=""
    for i in range(len(vuln_hyp_table)):
        if i%2==0:
            link=vuln_hyp_table[i].find_all('a',href=True)[0]['href'].strip()
            links.append(link)
        else:
            res=vuln_hyp_table[i].find_all('span',{'class':'badge'})
            for item in res:
                res_val=res_val+item.text.strip()+", "
            res_val=res_val[:-2]
            resources.append(res_val)
            res_val=""
    #print(links,resources)

    hyp=[]
    for i in range(len(links)):
        hyp.append({'link':links[i],'res':resources[i]})
    vuln_pub=page_soup.find('span',{'data-testid':'vuln-published-on'}).text.strip()
    vuln_last=page_soup.find('span',{'data-testid':'vuln-last-modified-on'}).text.strip()
    vuln_src=page_soup.find('span',{'data-testid':'vuln-current-description-source'}).text.strip()
    #print(vuln_pub,vuln_last,vuln_src)
    vuln_info={'cve':cvename,'version':cvss_ver,'source':vuln_src, 'published':vuln_pub,'modified':vuln_last, 'description':vuln_desc, 'base_score':cvss_score,'severity':cvss_sev}
    return vuln_info,vectors,hyp

@dash_bp.route("/ioc_search",methods=['GET', 'POST'])
def ioc_search():
	if request.method=="POST":
		text=request.form.get("ioc_in","").strip()
		print(text)
		if text=="":
			return render_template("ioc.html",ioc="",info=[],verdict=[],source="", sandbox="",itag="",vtag="",col="text-dark")
		elif "."in text:
			valid=False
			if "[.]" in text:
				text=text.replace("[.]",".")
			try:
				ipaddress.IPv4Network(text)
				valid=True
			except ValueError:
				valid=False
			if valid==True:
				print("IP4 address")
				if ipaddress.ip_address(text).is_private:
					print("Private IP, Can't Check Reputation.")
					return render_template("ioc.html",ioc="",info=[],sandbox="",verdict=[],source="Private IP, Can't Check Reputation",itag="",vtag="",col="text-dark")
				else: # valid IP
					data=AbuseIPDB_ReportsLookup(text)
					info=["ISP: "+str(data['isp']),"Country: "+ str(data['countryCode']),"Domain: "+str(data['domain'])]
					verdict=["Total Reports: "+ str(data['totalReports']),"Abuse Confidence Score: "+str(data['abuseConfidenceScore'])]
					if int(data['abuseConfidenceScore'])>70:
						col="text-danger"
					else:
						col="text-dark"
					return render_template("ioc.html", ioc="IP: "+text,info=info,sandbox="https://www.abuseipdb.com/check/"+text,sand_text="View in AbuseIPDB",verdict=verdict,source="AbuseIP DB",itag="Info: ",vtag="Verdict: ",col=col)

			else:
				if text[:4] !="http":
					text="https://"+text

				if "[:]" in  text:
					text=text.replace("[:]",":")

				if "__;" in text:
					text=text.split("__;")[0]
				if "https://urldefense.com/v3/__https:/" in text:
					text="https://"+text[35:]
				if "https://urldefense.com/v3/__http:/" in text:
					text="https://"+text[34:]

				sandbox=""
				valid=validators.url(text)
				if valid==True:
					warnings.filterwarnings('ignore')
					print("URL")
					sandbox="https://saasisolation.com/browser?traceToken=dash-create-url&url="+urllib.parse.quote(text,safe='')
					url=text
					vt_res = VT_URLsubmit(url)
					urlscan_res = URLSCANIO_submit(url)
					time.sleep(15)
					score, verdict,vtlink,col = VT_URLfetch(vt_res)
					uresults=URLSCAN_fetch(urlscan_res)
					ver, brand, info = URLSCAN_verdict(uresults)
					verdict=["VirusTotal Score: "+str(score),"VirusTotal verdict: "+verdict,"VirusTotal Link: "+vtlink,"URLScan.io Verdict: "+ver,"URLScan.io Brand: "+brand]
					return render_template("ioc.html",ioc="URL: "+ defangURL(url),sandbox=sandbox,sand_text="Run in Proofpoint Sandbox",source="VirusTotal/URLScan.IO",verdict=verdict,itag="Info: ", vtag="Verdict: ", info=info,col=col)
				else:
				    print("Invalid IP/URL")
				    return render_template("ioc.html",ioc="Invalid IP/URL", sandbox="", info=[],verdict=[],source="",itag="",vtag="",col="text-dark")

		elif len(text) in [32,40, 64, 128]:
		    valid=False
		    try:
		        z=int(text,16)
		        valid=True
		    except ValueError:
		        valid=False
		    if valid==True: #hash
		        verdict,col,info=VT_hash(text)
		        print(verdict)
		        return render_template("ioc.html",ioc="Hash: "+text,verdict=verdict, col=col,source="VirusTotal",itag="Info: ", vtag="Verdict: ", info=info)
		else:
			print("Invalid Input")
			return render_template("ioc.html",ioc="Invalid Input",info=[],verdict=[],source="", sandbox="",itag="",vtag="",col="text-dark")
	return render_template("ioc.html",ioc="",info=[],verdict=[],source="", sandbox="",v_n=0,i_n=0,itag="",vtag="",col="text-dark")

@dash_bp.route("/cve_hub",methods=['GET', 'POST'])
def cve_hub():
	logs=json.load(open("application/logs/cve_news.json"))
	for item in logs:
		if "," in item['cve']:
			logs.remove(item)
	base_url="https://nvd.nist.gov/vuln/detail/"
	if request.method=="POST":
		text=request.form.get("cve_in","").strip()
		if text=="":
			return render_template("cve.html",data=logs,total=len(logs),info="")
		else:
			check=requests.get(base_url+text)
			if check.status_code != 200: #webpage doesn't exist or be loaded
				return render_template("cve.html",data=logs,total=len(logs),info="Webpage doesn't exist or can't be loaded")
			else:
				cve_info,att_info,res=cveSearch(text)
				info_keys=list(cve_info.keys())
				vec={}
				for i in range(len(att_info)):
					k=list(att_info[i].keys())
					vec[k[0]]=att_info[i][k[0]]
				att_keys=list(vec.keys())
				return render_template("cve.html",data=logs,total=len(logs),info_keys=info_keys,cve_info=cve_info,att_keys=att_keys,att_info=vec,info="CVE INFO:",res=res)

	return render_template("cve.html",data=logs,total=len(logs),info="")

@dash_bp.route("/threat_hub",methods=['GET', 'POST'])
def threat_hub():
	detailed=json.load(open("application/logs/detailed_news.json"))
	headlines=json.load(open("application/logs/headlines.json"))
	sources=["All"]
	chosen=detailed
	src_selected=0
	for item in detailed:
		if item['source'] not in sources:
			sources.append(item['source'])

	if request.method=="POST":
		src_select=request.form.get("source_select","")

		if src_select!="":
			if int(src_select)==0:
				chosen=detailed
			elif int(src_select)>0 and int(src_select)<=len(detailed)+1:
				key=sources[int(src_select)]
				chosen=[]
				for item in detailed:
					if item['source']==key:
						chosen.append(item)
			src_selected=int(src_select)
	return render_template("threat.html",headlines=headlines,detailed=chosen,srcs=sources,src_selected=src_selected)


@dash_bp.route("/events",methods=['GET', 'POST'])
def events():
	logs=json.load(open("application/logs/events.json"))
	return render_template("events.html",events=logs)