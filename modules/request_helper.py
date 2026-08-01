import time
import requests
from config import REQUEST_DELAY, USER_AGENT, REQUEST_TIMEOUT

session = requests.Session()

session.headers.update({
    "User-Agent": USER_AGENT
})

def safe_get(url):

    time.sleep(REQUEST_DELAY)

    return session.get(

        url,

        timeout=REQUEST_TIMEOUT,

        allow_redirects=True

    )