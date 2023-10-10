import requests
from urllib.request import Request, urlopen
from bs4 import BeautifulSoup
import html5lib
from datetime import datetime as dt
import json
import re

def parseTalosVuln(item):
    text=item.replace("  ","")
    tlist=text.split("  ")[0].split("\n\n")
    finlist={}
    j=1
    taglist=['vuln_name','discovered_on','cve','cvss']
    for i in range(len(tlist)):
        if tlist[i]=="":
            j+=1
            continue
        finlist[taglist[i-j]]=tlist[i].strip()
    return finlist

def talosintelligence(dlimit=30):
    URL = "https://talosintelligence.com/vulnerability_reports"
    req= Request(URL, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
       'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
       'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
       'Accept-Encoding': 'none',
       'Accept-Language': 'en-US,en;q=0.8',
       'Connection': 'keep-alive'})
    webpage=urlopen(req).read()
    soup=BeautifulSoup(webpage,'html.parser')
    #print(soup.prettify())
    items=[]
    x=[]
    for tag in soup.find_all('tr'):
        x.append(tag)
        items.append(tag.text)
    count=2
    intel_list=[]
    while True: 
        item=items[count]
        idict=parseTalosVuln(item)
        y=str(dt.now()).split(' ')[0]
        diffdays=(dt.strptime(y, "%Y-%m-%d") - dt.strptime(idict['discovered_on'], "%Y-%m-%d")).days
        if diffdays>dlimit:
            break
        count+=1
        intel_list.append(idict)
    #json.dump(intel_list,open("talos.json","w"))
    return intel_list
#talos_intel=talosintelligence(90)
#print(talos_intel)

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

#print(news)
def events():
    URL = "https://go.crowdstrike.com/CrowdStrike-Events.html"
    req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    webpage=urlopen(req).read()
    page_soup=BeautifulSoup(webpage,'html.parser')

    cards=page_soup.find_all('div',{'class':'mktoText eventBlock'})
    card_body=[]
    print(cards)
    for item in cards:
        title=item.find('div',{'class':'eventTitle'}).text.strip()
        location=item.find('div',{'class':'eventLocation'}).text.strip()
        etype=item.find('div',{'class':'eventWhat'}).text.strip()
        link=item.find('div',{'class':'eventLink'}).find('a')['href'].strip()
        date=item.find('div',{'class':'eventDates'}).text.strip()
        card_body.append({"Event":title,"Location":location,"Type":etype,"Link":link,"Dates":date})
    json.dump(card_body,open("logs/events.json","w"))
    print(card_body)

def dcheck():
    month=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
    eve=json.load(open("logs/events.json"))
    events=[]
    for i in range(len(eve)):
        item=eve[i]
        temp=item['Dates'].split(", ")
        y=temp[1]
        dend=[]
        if "-" in temp[0]:
            t=temp[0].split("-")
            if len(str(t[1]))<=2:
                t[1]=t[0][:3]+" "+str(t[1])
            temp[0]=t[1]

        dend=temp[0].split(" ")
        dend[0]=dend[0][:3]
        print(dend)
        m=month.index(dend[0])+1
        if m<=9:
            m="0"+str(m)
        d=dend[1]

        if len(d)==1:
            d="0"+d
        d1=str(y)+"-"+str(m)+"-"+d
        d0=str(dt.now()).split(' ')[0]
        print(d1,d0)
        diff=(dt.strptime(d0, "%Y-%m-%d")-dt.strptime(d1, "%Y-%m-%d")).days
        print(diff)

        if diff>0:
            continue
        else:
            events.append(item)
            break

    print(i,eve[i])
dcheck()
