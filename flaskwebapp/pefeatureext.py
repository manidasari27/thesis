#Feature Extraction
# importing required packages for this section
import re
import whois
import urllib
import urllib.request
from datetime import datetime
import re
from urllib.parse import urlparse,urlencode
import ipaddress
import csv
import requests

with open('top-1m.csv') as f:
  reader = csv.reader(f)
  alexa = list(reader)

#----Domain feature extraction from url

# check web page rank from top 1 millon list
def traffic_check(url, alexa):
  domain = extractdom(url)
  try:
    rank = [i for i, v in enumerate(alexa) if v[1] == domain][0] + 1
  except:
    return 1
  if rank <100000:
    return 0
  else:
    return 1 #phish

#
def dmage(domain_name):
  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date
  if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
    try:
      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if ((expiration_date is None) or (creation_date is None)):
      return 1
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
      return 1
  else:
    ageofdomain = abs((expiration_date - creation_date).days)
    if ((ageofdomain/30) < 6):
      age = 1  #phish
    else:
      age = 0
  return age

#
def dmend(domain_name):
  expiration_date = domain_name.expiration_date
  if isinstance(expiration_date,str):
    try:
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if (expiration_date is None):
      return 1
  elif (type(expiration_date) is list):
      return 1
  else:
    today = datetime.now()
    end = abs((expiration_date - today).days)
    if ((end/30) < 6):
      end = 0
    else:
      end = 1  #phish
  return end



#---Address based feature extraction from url
#
def extractdom(url):

  domain = urlparse(url).netloc
  if re.match(r"^www.",domain):
    domain = domain.replace("www.","")
  return domain

#
def checkip(url):
  try:
    ipaddress.ip_address(url)
    ip = 1   #phish
  except:
    ip = 0    
  return ip

#
def symbol(url):
  if "@" in url:
    at = 1    #phish
  else:
    at = 0    
  return at

#
def extractlenght(url):
  if len(url) < 54:
    length = 0            
  else:
    length = 1    #phish        
  return length
     

#
def extractdepth(url):
  s = urlparse(url).path.split('/')
  depth = 0   
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth



#
def redirecting(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1   #phish
    else:
      return 0
  else:
    return 0


#
def checkhttpdomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 0
  else:
    return 1   #phish
     

#
services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

def tinyURL(url):
    match=re.search(services,url)
    if match:
        return 1  #suspected phishing since url is shortend
    else:
        return 0



#
def prefixsuffixcheck(url):
    if '-' in urlparse(url).netloc:
        return 1 # phish
    else:
        return 0 # legit


#----Content Based Feature extraction

def iframe(response):
  if response == "":
      return 0
  else:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          return 1  #phish
      else:
          return 0


#
def WebsiteForwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1  #phish

#
def DisableRightClick(response):
  if response == "":
    return 1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1  #phish

#
def StatusBarCust(response): 
  if response == "" :
    return 1
  else:
    if re.findall("<script>.+onmouseover.+</script>", response.text):
      return 1   #phish
    else:
      return 0

#
def IframeRedirection(response):
  if response == "":
      return 0
  else:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          return 1   #phish
      else:
          return 0

#
def LinksPointingToPage(response):
  try:
      number_of_links = len(re.findall(r"<a href=", response.text))
      if number_of_links == 0:
          return 1
      elif number_of_links <= 2:
          return 0
      else:
          return -1
  except:
      return -1

#
def GoogleIndex(url):
  try:
      site = search(url, 5)
      if site:
          return 1
      else:
          return -1
  except:
      return 1



#Function to extract features
def URLID(url,class1):

  cols = []
  cols.append(extractdom(url))
  cols.append(checkip(url))
  cols.append(symbol(url))
  cols.append(extractlenght(url))
  cols.append(extractdepth(url))
  cols.append(redirecting(url))
  cols.append(checkhttpdomain(url))
  cols.append(tinyURL(url))
  cols.append(prefixsuffixcheck(url))

  #Domain based features (4)
  dns = 0
  try:
    domain_name = whois.whois(urlparse(url).netloc)
  except:
    dns = 1

  cols.append(dns)
  cols.append(traffic_check(url,alexa))
  cols.append(1 if dns == 1 else dmage(domain_name))
  cols.append(1 if dns == 1 else dmend(domain_name))

  # HTML & Javascript based features
  try:
    response = requests.get(url)
  except:
    response = ""

  cols.append(IframeRedirection(response))
  cols.append(StatusBarCust(response))
  cols.append(DisableRightClick(response))
  cols.append(WebsiteForwarding(response))
  cols.append(LinksPointingToPage(response))
  cols.append(GoogleIndex(url))

  cols.append(class1)
  return cols



#Function to extract features
def urlfeature_extractor(url):

  cols = []
  cols.append(extractdom(url))
  cols.append(checkip(url))
  cols.append(symbol(url))
  cols.append(extractlenght(url))
  cols.append(extractdepth(url))
  cols.append(redirecting(url))
  cols.append(checkhttpdomain(url))
  cols.append(tinyURL(url))
  cols.append(prefixsuffixcheck(url))

  #Domain based features (4)
  dns = 0
  try:
    domain_name = whois.whois(urlparse(url).netloc)
  except:
    dns = 1

  cols.append(dns)
  cols.append(traffic_check(url,alexa))
  cols.append(1 if dns == 1 else dmage(domain_name))
  cols.append(1 if dns == 1 else dmend(domain_name))

  cols.append(GoogleIndex(url))

  return cols



