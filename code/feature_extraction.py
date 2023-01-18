import pandas as pd
from urllib.parse import urlparse,urlencode
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import requests

# Loading phishing data
phishing_data=pd.read_csv("Datasets/phishing.csv")
#randomly taking the 5000 samples
phishing_sample=phishing_data.sample(n=5000,random_state=10).copy()
#re-indexing from 0
phishing_sample=phishing_sample.reset_index(drop=True)
# Storing the sampled phishing data in csv file
phishing_sample.to_csv('Datasets/phishing_data_sample.csv', index= False)


#Loading legitimate data

legitimate_data=pd.read_csv("Datasets/legitimate.csv")
# assigning the column name
legitimate_data.columns=["urls"]
#randomly taking the 5000 samples
legitimate_sample=legitimate_data.sample(n=5000,random_state=10).copy()
#re-indexing from 0
legitimate_sample=legitimate_sample.reset_index(drop=True)
# Storing the sampled legitimate data in csv file
legitimate_sample.to_csv('Datasets/legitimate_data_sample.csv', index= False)


# 'Have_At'
#checking if there is "@" symbol in the URL
def checkAtSymbol(url):
    if "@" in url:
        return 1   #phishing
    else:
        return 0    #legitimate
# _____________________________________________________________________

# 'URL_Length'
#finding the length of url
def getLength(url):
  if len(url) < 82:
    return 0    #legitimate        
  else:
    return 1    #phishing
# _____________________________________________________________________


# 'URL_Depth'
#finding the depth of url
def getDepth(url):
  split_url = urlparse(url).path.split('/')
  depth = 0
  for i in range(len(split_url)):
    if len(split_url[i]) != 0:
      depth = depth+1
  return depth
# _____________________________________________________________________

# 'TinyURL'
#shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
#checking if the url is using any shortening services
def checktinyURL(url):
    tinyURL_match=re.search(shortening_services,url)
    if tinyURL_match:
        return 1    #phishing
    else:
        return 0    #legitimate
# _____________________________________________________________________

# 'Prefix_Suffix'
#checking if there is prefix or suffix separated by "-" in the domain name
def checkPrefixSuffix(url):
    domainName = urlparse(url).netloc
    if '-' in domainName:
        return 1  #phishing
    else:
        return 0  #legitimate
# _____________________________________________________________________

#  'DNS_Record'
# _____________________________________________________________________

# 'Domain_Age'
#finding domain age
def domainAge(domain_name):
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
      return 1      # Phishing
    else:
      return 0      # Legitimate
# _____________________________________________________________________

# 'End_Domain'

#finding domain age
def domainEnd(domain_name):
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
      end = 1
  return end
# _____________________________________________________________________

# 'iFrame'
#checking iframe in webpage content
def iframe(response):
    try:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
        return 0     # Legitimate
      else:
        return 1     # Phishing
    except:
        return 1
# _____________________________________________________________________

# 'Web_Forwards'
# Checks the number of forwardings (Web_Forwards)    
def forwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1
# _____________________________________________________________________


# Computing the features

#Function to extract features
def getFeatures(url):

  features = []
  
  features.append(checkAtSymbol(url))
  features.append(getLength(url))
  features.append(getDepth(url))
  features.append(checktinyURL(url))
  features.append(checkPrefixSuffix(url))
  
  #Domain-Based features (3)
  dns = 0
  try:
    domain_name = whois.whois(urlparse(url).netloc)
  except:
    dns = 1

  features.append(dns)
  features.append(1 if dns == 1 else domainAge(domain_name))
  features.append(1 if dns == 1 else domainEnd(domain_name))

  #Content-Based features (4)
  try:
    response = requests.get(url)
  except:
    response = ""
    
  features.append(iframe(response))
  features.append(forwarding(response))

  return features




