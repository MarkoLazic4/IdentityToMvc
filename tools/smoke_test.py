"""Smoke test for a running app created from the template (used by CI).

Registers an account, follows the confirmation link that Development shows on the
"check your email" page, logs in and checks that the given pages answer 200.
Usage: smoke_test.py <base-url> [page ...]
"""
import sys, re, ssl, urllib.request, urllib.parse, http.cookiejar, html
base=sys.argv[1]
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
jar=http.cookiejar.CookieJar()
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**k): return None
op=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),urllib.request.HTTPCookieProcessor(jar),NoRedirect)
def req(path,data=None):
    r=urllib.request.Request(base+path,data=urllib.parse.urlencode(data).encode() if data else None,headers={'Accept-Language':'en'})
    try: resp=op.open(r); return resp.status, resp.headers, resp.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.headers, e.read().decode()
def token(page): return re.search(r'name="__RequestVerificationToken" type="hidden" value="([^"]+)"',page).group(1)
failures=0
email='smoke@example.test'; pw='Blue-Kettle-42!'
s,h,p=req('/User/Account/Register')
s,h,p=req('/User/Account/Register',{'Input.Email':email,'Input.Password':pw,'Input.ConfirmPassword':pw,'__RequestVerificationToken':token(p)})
print('register',s,h.get('Location'))
s,h,p=req(h['Location'])
link=html.unescape(re.search(r'href="([^"]*ConfirmEmail[^"]*)"',p).group(1))
s,h,p=req(link.replace(base,'')); print('confirm',s)
s,h,p=req('/User/Account/Login')
s,h,p=req('/User/Account/Login',{'Input.Email':email,'Input.Password':pw,'__RequestVerificationToken':token(p)})
print('login',s,h.get('Location'))
assert s==302 and h.get('Location','').endswith('/Home/Index'), 'login failed'
for path in sys.argv[2:]:
    s,h,p=req(path); print(path,s,h.get('Location') or '')
    if s!=200: failures+=1
sys.exit(1 if failures else 0)
