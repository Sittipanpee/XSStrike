import random
import requests
import time
from urllib3.exceptions import ProtocolError
import warnings

import core.config
from core.utils import converter, getVar
from core.log import setup_logger

logger = setup_logger(__name__)

warnings.filterwarnings('ignore')  # Disable SSL related warnings

# ─── DrissionPage browser engine for Cloudflare bypass ───
_browser_session = None

def _get_browser_session():
    """Lazy-init a DrissionPage Chromium tab."""
    global _browser_session
    if _browser_session is None:
        try:
            from DrissionPage import ChromiumOptions, ChromiumPage
            options = ChromiumOptions()
            options.set_argument('--disable-blink-features=AutomationControlled')
            options.set_argument('--disable-dev-shm-usage')
            options.set_argument('--no-sandbox')
            _browser_session = ChromiumPage(addr_or_opts=options)
            logger.info('DrissionPage browser engine started (Cloudflare bypass mode)')
        except Exception as e:
            logger.error(f'Failed to start DrissionPage browser: {e}')
            raise
    return _browser_session


def browser_requester(url, data, headers, GET, delay, timeout):
    """
    DrissionPage-based requester that executes JavaScript — bypasses
    Cloudflare JS challenges, Fugare, PerimeterX, Shape Security, etc.
    """
    import urllib.parse
    time.sleep(delay)
    tab = _get_browser_session()

    if GET:
        if data:
            query = urllib.parse.urlencode(data)
            full_url = f'{url}?{query}' if '?' not in url else f'{url}&{query}'
        else:
            full_url = url
        tab.get(full_url, timeout=timeout)
    else:
        # DrissionPage uses tab.post() for POST requests
        tab.post(url, data=data, timeout=timeout)

    # Extract response — tab.html gives rendered DOM, tab.response has HTTP info
    class _BrowserResponse:
        def __init__(self, tab):
            self.text = tab.html
            self.url = tab.url
            # Try to get real status code from response metadata
            try:
                self.status_code = tab.response.status_code
            except Exception:
                self.status_code = 200
            try:
                self.headers = dict(tab.response.headers)
            except Exception:
                self.headers = {}

    return _BrowserResponse(tab)


def requester(url, data, headers, GET, delay, timeout):
    # ─── Route to browser engine if --browser flag is set ───
    if core.config.use_browser:
        return browser_requester(url, data, headers, GET, delay, timeout)

    if getVar('jsonData'):
        data = converter(data)
    elif getVar('path'):
        url = converter(data, url)
        data = []
        GET, POST = True, False
    time.sleep(delay)
    user_agents = ['Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991']
    if 'User-Agent' not in headers:
        headers['User-Agent'] = random.choice(user_agents)
    elif headers['User-Agent'] == '$':
        headers['User-Agent'] = random.choice(user_agents)
    logger.debug('Requester url: {}'.format(url))
    logger.debug('Requester GET: {}'.format(GET))
    logger.debug_json('Requester data:', data)
    logger.debug_json('Requester headers:', headers)
    try:
        if GET:
            response = requests.get(url, params=data, headers=headers,
                                    timeout=timeout, verify=False, proxies=core.config.proxies)
        elif getVar('jsonData'):
            response = requests.post(url, json=data, headers=headers,
                                    timeout=timeout, verify=False, proxies=core.config.proxies)
        else:
            response = requests.post(url, data=data, headers=headers,
                                     timeout=timeout, verify=False, proxies=core.config.proxies)
        return response
    except ProtocolError:
        logger.warning('WAF is dropping suspicious requests.')
        logger.warning('Scanning will continue after 10 minutes.')
        time.sleep(600)
    except Exception as e:
        logger.warning('Unable to connect to the target.')
        return requests.Response()
