#---------------------------Imports-------------------------#
import requests
from urllib.request import Request, urlopen
from bs4 import BeautifulSoup
import html5lib
from datetime import datetime as dt
import json
import re
import sys
#-----------------------------------------------------------#

#----------------------------Talos--------------------------#
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

def talosintelligence(dlimit=90):
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

#-----------------------------------------------------------#

#--------------------------Fortinet-------------------------#
def fortinet():
    filepath='logs/fortinet.json'
    URL = "https://www.fortinet.com/fortiguard/outbreak-alert"
    req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    webpage=urlopen(req).read()
    page_soup=BeautifulSoup(webpage,'html.parser')
    items=[]
    cards=page_soup.find_all('div',{'class':'alert-cell'})
    for card in cards:
        title=card.find_all('div',{'class':'alert-title'})[0].text.strip()
        #severity=card.find_all('div',{'class':'alert-data'})[0].text.strip().split('\n')[1].split(':')[1].strip()
        adesc=card.find_all('div',{'class':'alert-desc'})
        desc=adesc[1].text.split(':')[1].strip()
        link=card.find_all('div',{'class':'alert-link'})[0].find_all('a',href=True)[0]['href'].strip()
        items.append({'source':'FortiGuard Labs Fortinet','title':title,'desc':desc,'link':link})
    #print(items)
    if items != None:
        json.dump(items,open(filepath,'w'))
        return items
    else: 
        return None
#-----------------------------------------------------------#

#-------------------------Proofpoint------------------------#
def proofPoint():
    filepath='logs/proofpoint.json'
    URL = "https://www.proofpoint.com/us/blog/threat-insight"
    req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    webpage=urlopen(req).read()
    soup=BeautifulSoup(webpage,'html.parser')
    #print(soup.prettify())
    items=[]
    links=soup.find_all("a", {"class": "blog-mosaic__link"})
    titles=soup.find_all("div", {"class": "blog-mosaic__title"})
    #print(titles)
    for i in range(len(links)):
        link=links[i]['href'].strip()
        title=titles[i].text.strip()
        if link!="":
            link="https://www.proofpoint.com"+link
            items.append({"source":"ProofPoint","link":link,"title":title})
    title_main=soup.find_all("a", {"class": "blog-teaser__title"})
    for i in range(len(title_main)):
        link=title_main[i]['href'].strip()
        if link!="":
            link="https://www.proofpoint.com"+link
        title_name=title_main[0].text.strip()
        items.append({"source":"ProofPoint","link":link,"title":title_name})
    #print(items)
    if items != None:
        json.dump(items,open(filepath,'w'))
        return items
    else: 
        return None
#-----------------------------------------------------------#

#------------------------SecurityWeek-----------------------#
def securityWeek():
    filepath='logs/securityweek.json'
    URL = "https://www.securityweek.com/category/data-breaches/"
    req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    webpage=urlopen(req).read()
    page_soup=BeautifulSoup(webpage,'html.parser')
    #print(page_soup.prettify())
    items=[]
    for tag in page_soup.find_all("div",{"class":"zox-art-title"}):
        link=tag.find_all("a",href=True)[0]['href'].strip()
        items.append({"source":"Security Week","link":link,"title":tag.text.strip()})
    #print(items)
    if items != None:
        json.dump(items,open(filepath,'w'))
        return items
    else: 
        return None
#-----------------------------------------------------------#

#-------------------------OwaspTop10------------------------#
def getOwaspTop10():
    filepath='logs/owasp.json'
    URL = "https://owasp.org/www-project-top-ten/"
    req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    webpage=urlopen(req).read()
    page_soup=BeautifulSoup(webpage,'html.parser')
    #print(page_soup.prettify())
    items=[]
    sec=page_soup.find_all("section",{"id":"sec-main"})[0]
    links=sec.find_all("a")
    strongs=sec.find_all("strong")
    descs=sec.find_all("li")
    for i in range(len(links)):
        link=links[i]['href'].strip()
        strong=strongs[i].text.strip()
        desc=descs[i].text.strip()
        owaspid=strong.split("-")[0].strip()
        items.append({"_id":owaspid,"link":link,"attack":strong,"desc":desc})
    #print(items)
    if items != None:
        json.dump(items,open(filepath,'w'))
        return items
    else: 
        return None
#-----------------------------------------------------------#

#-------------------------SentinelOne-----------------------#
def sentinelOne():
    filepath='logs/sentinelone.json'
    URL = "https://www.sentinelone.com/blog/category/from-the-front-lines/"
    req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    webpage=urlopen(req).read()
    page_soup=BeautifulSoup(webpage,'html.parser')
    #print(page_soup.prettify())
    items=[]
    feat=page_soup.find_all("div",{"class":"featured"})
    feat_url=feat[0].find_all("a", href=True)[0]['href'].strip()
    feat_title=feat[0].find_all("h2")[0].text.strip()
    items.append({"title": feat_title,"link": feat_url})
    art=page_soup.find_all("article")
 
    for article in art:
        article_url=article.find_all("a", href=True)[0]['href'].strip()
        article_title=article.find_all("h2")[0].text.strip()
        items.append({"source":"SentinelOne","title": article_title, "link": article_url})
    #print(items)
    if items != None:
        json.dump(items,open(filepath,'w'))
        return items
    else: 
        return None
#-----------------------------------------------------------#

#-----------------------BleepingComputer--------------------#
def bleepingComputer():
    filepath='logs/bleepingcomputer.json'
    URL = "https://www.bleepingcomputer.com/tag/data-breach/"
    req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    webpage=urlopen(req).read()
    page_soup=BeautifulSoup(webpage,'html.parser')
    #print(page_soup.prettify())
    news_list=page_soup.find_all("div",{"class":"bc_latest_news_text"})
    items=[]
    for news in news_list:
        extract=news.find_all("h4")
        link=extract[0].find_all('a',href=True)[0]['href'].strip()
        title=extract[0].text.strip()
        desc=news.find_all("p")[0].text.strip()
        items.append({"source":"Bleeping Computer","title":title,"link":link,"desc":desc})
    #print(items)
    if items != None:
        json.dump(items,open(filepath,'w'))
        return items
    else: 
        return None
#-----------------------------------------------------------#

#---------------------------Tenable-------------------------#
def tenable():
    filepath='logs/tenable.json'
    URL = "https://www.tenable.com/blog/search?field_blog_section_tid=47"
    req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    webpage=urlopen(req).read()
    page_soup=BeautifulSoup(webpage,'html.parser')
    #print(page_soup.prettify())
    cards=page_soup.find_all('div',{'class':'blog-item__content'})
    items=[]
    for card in cards:
        news=card.find_all('a',href=True)[0]
        link="https://www.tenable.com"+news['href'].strip()
        title=news.text.strip()
        items.append({'source':'Tenable','title':title,'link':link})
    #print(items)
    if items != None:
        json.dump(items,open(filepath,'w'))
        return items
    else: 
        return None
#-----------------------------------------------------------#

#--------------------------ReSecurity-----------------------#
def reSecurity():
    filepath='logs/resecurity.json'
    URL = "https://www.resecurity.com/blog"
    req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    webpage=urlopen(req).read()
    page_soup=BeautifulSoup(webpage,'html.parser')
    cards=page_soup.find_all("a",{"class":"col-lg-11"})
    items=[]
    #print(cards)
    for card in cards:
        link="https://www.resecurity.com"+card['href'].strip()
        #print(link)
        text=card.find_all('div',{'class':'text-h4-size news-title'})[0].text.strip()
        #print(text)
        items.append({"source":"ReSecurity","title":text,"link":link})
    #print(items)
    if items != None:
        json.dump(items,open(filepath,'w'))
        return items
    else: 
        return None
#-----------------------------------------------------------#

#------------------------TheHackerNews----------------------#
def thehackerNews():
    filepath='logs/thehackernews'
    URL = "https://thehackernews.com/search/label/Vulnerability"
    req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    webpage=urlopen(req).read()
    page_soup=BeautifulSoup(webpage,'html.parser')
    cards=page_soup.find_all('div',{'class':'body-post clear'})
    v_items=[]
    for card in cards:
        link=card.find_all('a',href=True)[0]['href'].strip()
        title=card.find_all('h2',{'class':'home-title'})[0].text.strip().replace(u'\xa0', u' ')
        desc=card.find_all('div',{'class':'home-desc'})[0].text.strip().replace(u'\xa0', u' ')+"..."
        tags=card.find_all('span',{'class':'h-tags'})
        if len(tags)>=1:
            tags=tags[0].text
        else:
            tags="Vulnerability"
        v_items.append({'source':'TheHackerNews','link':link,'tags':tags,'title':title,'desc':desc})
    
    trending_cards=page_soup.find_all('div',{'class':'clear section'})[0]
    t_title=trending_cards.find_all('div',{'class':'pop-title'})
    t_link=trending_cards.find_all('a',href=True)
    t_items=[]
    for i in range(len(t_link)):
        title=t_title[i].text.strip()
        link=t_link[i]['href'].strip()
        t_items.append({'source':'TheHackerNews','title':title,'link':link})
        
    URL2 = "https://thehackernews.com/search/label/data%20breach"
    req2= Request(URL2, headers={'User-Agent': 'Mozilla/5.0'})
    webpage2=urlopen(req2).read()
    page_soup2=BeautifulSoup(webpage2,'html.parser')
    cards2=page_soup2.find_all('div',{'class':'body-post clear'})
    b_items=[]
    for card in cards2:
        link=card.find_all('a',href=True)[0]['href'].strip()
        title=card.find_all('h2',{'class':'home-title'})[0].text.strip().replace(u'\xa0', u' ')
        desc=card.find_all('div',{'class':'home-desc'})[0].text.strip().replace(u'\xa0', u' ')+"..."
        tags=card.find_all('span',{'class':'h-tags'})
        if len(tags)>=1:
            tags=tags[0].text
        else:
            tags="Data Breach"
        b_items.append({'source':'TheHackerNews','link':link,'tags':tags,'title':title,'desc':desc})

    if v_items != None:
        vpath=filepath+"_vuln.json"
        json.dump(v_items,open(vpath,'w'))
    if t_items != None:
        tpath=filepath+"_trend.json"
        json.dump(t_items,open(tpath,'w'))
    if b_items != None:
        bpath=filepath+"_breach.json"
        json.dump(b_items,open(bpath,'w'))
    return v_items,t_items,b_items
thehackerNews()
#-----------------------------------------------------------#

#------------------------DataBreaches-----------------------#
def dataBreaches(limit=5):
    filepath='logs/databreaches.json'
    baseURL = "https://www.databreaches.net/news/page/"
    items=[]
    for i in range(limit):
        URL = baseURL+str(i+1)+"/"
        req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
        webpage=urlopen(req).read()
        page_soup=BeautifulSoup(webpage,'html.parser')
        cards=page_soup.find_all('div',{'class':'entry-main'})
        for card in cards:
            title=card.find_all('h1',{'class':'entry-title'})[0].text.strip()
            link=card.find_all('a',href=True)[0]['href'].strip()
            desc=card.find_all('div',{'class':'entry-summary'})[0].text.replace(u'\xa0', u' ').strip()
            items.append({'source':'DataBreaches','title':title,'desc':desc,'link':link})
    #print(items)
    if items != None:
        json.dump(items,open(filepath,'w'))
        return items
    else: 
        return None
#-----------------------------------------------------------#

#-------------------------TechCrunch------------------------#
def techCrunch():
    filepath='logs/techcrunch.json'
    URL = "https://techcrunch.com/category/security/"
    req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    webpage=urlopen(req).read()
    page_soup=BeautifulSoup(webpage,'html.parser')
    cards=page_soup.find_all('a',{'class':'post-block__title__link'})
    items=[]
    for card in cards:
        title=card.text.strip()
        link=card['href'].strip()
        items.append({'source':'TechCrunch','title':title,'link':link})
    #print(items)
    if items != None:
        json.dump(items,open(filepath,'w'))
        return items
    else: 
        return None
#-----------------------------------------------------------#

#-----------------------RecordedFuture----------------------#
def recordedfuture():
    filepath='logs/recordedfuture.json'
    keys=['technology','cybercrime','nation-state']
    items=[]
    for i in range(len(keys)):
        URL = "https://therecord.media/news/"+keys[i]+"/feed"
        req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
        webpage=urlopen(req).read()
        page_soup=BeautifulSoup(webpage,'xml')
        cards=page_soup.find_all('item')
        for card in cards:
            title=card.find_all('title')[0].text.strip()
            link=card.find_all('link')[0].text.strip()
            desc=str(card.find_all('description')[0].text.split('\n')[-1].strip()+"...")
            desc=desc.replace("&#39;","'")
            if "<a href=" in desc:
                desc=re.subn('<[a-z 0-9A-Z=":./\-%_]*>','',desc)[0]
            items.append({'source':'RecordedFuture','title':title,'link':link,'desc':desc})

    if items != None:
        #print(items)
        json.dump(items,open(filepath,'w'))
        return items
    else:
        return None
#-----------------------------------------------------------#

#---------------------------Events--------------------------#

def upcomingevents():
    URL = "https://go.crowdstrike.com/CrowdStrike-Events.html"
    req= Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
    webpage=urlopen(req).read()
    page_soup=BeautifulSoup(webpage,'html.parser')

    cards=page_soup.find_all('div',{'class':'mktoText eventBlock'})
    items=[]
    #print(cards)
    for item in cards:
        title=item.find('div',{'class':'eventTitle'}).text.strip()
        location=item.find('div',{'class':'eventLocation'}).text.strip()
        etype=item.find('div',{'class':'eventWhat'}).text.strip()
        link=item.find('div',{'class':'eventLink'}).find('a')['href'].strip()
        date=item.find('div',{'class':'eventDates'}).text.strip()
        items.append({"Event":title,"Location":location,"Type":etype,"Link":link,"Dates":date})

    if items!=None:

        return items
    else:
        return None
#-----------------------------------------------------------#

#------------------------Agrregate-----------------------#
def aggregate():
    headlines=[]
    cve_news=[]
    detailed_news=[]
    events=[]
    #---------------------------------------------------
    try:
        forti=fortinet()
    except:
        print('Fortinet Module is Crashing')
    else:
        if forti!=None:
            for item in forti:
                detailed_news.append(item)
    #----------------------------------------------------
    try:
        talos=talosintelligence()
    except:
        print('TalosIntelligence Module is Crashing')
    else:
        if talos!=None:
            for item in talos:
                cve_news.append(item)
    #---------------------------------------------------
    try:
        pp=proofPoint()
    except:
        print('Proofpoint Module is Crashing')
    else:
        if pp!=None:
            for item in pp:
                headlines.append(item)
    #---------------------------------------------------
    try:
        sw=securityWeek()
    except:
        print('SecurityWeek Module is Crashing')
    else:
        if sw!=None:
            for item in sw:
                headlines.append(item)
    #---------------------------------------------------
    try:
        s1=sentinelOne()
    except:
        print('SentinelOne Module is Crashing')
    else:
        if s1!=None:
            for item in s1:
                headlines.append(item)
    #---------------------------------------------------
    try:
        t=tenable()
    except:
        print('Tenable Module is Crashing')
    else:
        if t!=None:
            for item in t:
                headlines.append(item)
    #---------------------------------------------------
    try:
        rs=reSecurity()
    except:
        print('ReSecurity Module is Crashing')
    else:
        if rs!=None:
            for item in rs:
                headlines.append(item)
    #---------------------------------------------------
    try:
        tc=techCrunch()
    except:
        print('TechCrunch Module is Crashing')
    else:
        if tc!=None:
            for item in tc:
                headlines.append(item)
    #---------------------------------------------------
    try:
        db=dataBreaches()
    except:
        print('DataBreaches Module is Crashing')
    else:
        if db!=None:
            for item in db:
                detailed_news.append(item)
    #---------------------------------------------------
    try:
        tc=techCrunch()
    except:
        print('TechCrunch Module is Crashing')
    else:
        if tc!=None:
            for item in tc:
                headlines.append(item)
    #---------------------------------------------------
    try:
        rf=recordedfuture()
    except:
        print('RecordedFuture Module is Crashing')
    else:
        if rf!=None:
            for item in rf:
                detailed_news.append(item)
    #---------------------------------------------------
    try:
        eve=upcomingevents()
    except:
        print('Events Module is Crashing')
    else:
        if eve!=None:
            events=eve

    if events!=[]:
        json.dump(events,open("logs/events.json","w"))
    if headlines != []:
        json.dump(headlines,open('logs/headlines.json','w'))
    if detailed_news != []:
        json.dump(detailed_news,open('logs/detailed_news.json','w'))
    if cve_news != []:
        json.dump(cve_news,open('logs/cve_news.json','w'))
aggregate()
