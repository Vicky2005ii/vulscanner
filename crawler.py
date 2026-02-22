import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def crawl_site(url):
    urls = [url]

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        for link in soup.find_all("a"):
            href = link.get("href")
            if href:
                full_url = urljoin(url, href)
                urls.append(full_url)

    except:
        pass

    return list(set(urls))
