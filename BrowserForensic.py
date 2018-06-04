#!/usr/bin/env python

import optparse

try:
    from Chrome_Forensic import *
    from Firefox_Forensic import *
except ImportError:
    sys.exit(
        "Could not find Chrome_Forensic.py and Firefox_Forensic... Please download the full toolkit from https://github.com/VuDucNguyen9x/BrowserForensic")

print("""
    ############ A Python script to read web browser data #########
    #                     Coded by VuDucNguyen9x                  #
    #             can read Forms Data, Cookies, Searches,         #
    #         Downloads, History and Password to name a few!      #
    ###############################################################
    """)
parser = optparse.OptionParser(
    "Usage: python %prog -w <webbrowser> -t <target> -b <(optional) web browser database path> --min_time <(optional) minimum entry time>" \
    + " --max_time <(optional) maximum entry time> --domain <(optional) Target is a host/domain> --android <(optional) Target is a firefox android database?> or python %prog -h for help")

target_help = "can take one of 4 values: history, searches, cookies, forms_history, logins or downloads"
parser.add_option("-t", dest="target", type="string", help=target_help)

wb_help = "can take one of 2 values: chrome, firefox"
parser.add_option("-w", dest="wb", type="string", help=wb_help)

db_help = ("""The full path of the web browser database file to parse. By Default:
- Google Chrome:
 Android profile -> data/data/com.android.chrome/app_chrome/Default/
 WinXP profile -> C:\\Documents and Settings\\%%USERNAME%%\\Application Support\\Google\\Chrome\\Default
 Win7+ profile -> C:\\Users\\%%USERNAME%%\\AppData\\Local\\Google\\Chrome\\User Data\\Default
 MacOS profile -> /Users/$USER/Library/Application Support/Google/Chrome/Default
 Unix profile  -> /home/$USER/.config/google-chrome/Default
- Firefox:
 WinXP profile -> C:\\Documents and Settings\\%%USERNAME%%\\Application Data\\Mozilla\\Firefox\\Profiles
 Win7+ profile -> C:\\Users\\%%USERNAME%%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles
 MacOS profile -> /Users/$USER/Library/Application\ Support/Firefox/Profiles
 Unix profile  -> /home/$USER/.mozilla/firefox
""")
parser.add_option("-b", dest="db", type="string", help=db_help)

min_help = "enter if target isn't 'cookies' to read items after a given date and time, must be a string separated by: YYYY:MM:DD HH:MM:SS"
parser.add_option("--min_time", dest="min", type="string", help=min_help)

max_help = "enter if target isn't 'cookies' to read items before a given date and time, must be a string separated by: YYYY:MM:DD HH:MM:SS"
parser.add_option("--max_time", dest="max", type="string", help=max_help)

hd_help = "enter if target function is cookies or logins to look for results corresponding to a specific host/domain. Default None"
parser.add_option("--domain", dest="host_domain", type="string", help=hd_help)

android_help = "True if target database is a firefox android database. default False"
parser.add_option("--android", dest="droid", type="string", help=android_help)

(options, args) = parser.parse_args()

if not options.target:
    sys.exit("please enter a target:\n\n%s" % parser.usage)

if options.wb not in ("chrome", "firefox"):
    sys.exit("Unrecognized target web browser!")

if options.target not in ("cookies", "history", "searches", "downloads", "logins", "forms_history"):
    sys.exit("Unrecognized target function!")

#wb = options.wb
db = options.db
hd = options.host_domain

if options.min:
    min_time = time_encode(options.min)
else:
    min_time = 0
if options.max:
    max_time = time_encode(options.min)
else:
    max_time = 9 ** 18  # Chrome: 6357-04-24 10:14:56.999121 ; Firefox: 6726-04-24 10:14:56.999121

if options.wb.lower() == "chrome":
    if options.target.lower() == "cookies":
        if not db:
            db = get_chrome_db("cookies")
        read_chrome_cookies(db, tm_min=min_time, tm_max=max_time, host=hd)
    elif options.target.lower() == "history":
        if not db:
            db = get_chrome_db("history")
        read_chrome_history(db, tm_min=min_time, tm_max=max_time, host=hd)
    elif options.target.lower() == "searches":
        if not db:
            db = get_chrome_db("history")
        read_chrome_searches(db)
    elif options.target.lower() == "downloads":
        if not db:
            db = get_chrome_db("history")
        read_chrome_downloads(db, tm_min=min_time, tm_max=max_time)
    elif options.target.lower() == "logins":
        if not db:
            db = get_chrome_db("Login Data")
        read_chrome_logins(db, tm_min=min_time, tm_max=max_time, domain=hd)
elif options.wb.lower() == "firefox":
    try:
        android = eval(options.droid)
    except Exception:
        android = False

    if options.target.lower() == "cookies":
        if not db:
            db = get_firefox_db("cookies.sqlite")
        read_moz_cookies(db)
    elif options.target.lower() == "history":
        if not db:
            db = get_firefox_db("places.sqlite")
        read_moz_history(db, min_time, max_time, android=android, google=False)
    elif options.target.lower() == "searches":
        if not db:
            db = get_firefox_db("places.sqlite")
        read_moz_searches(db)
    elif options.target.lower() == "logins":
        if not db:
            db = get_firefox_db("logins.json")
        read_moz_logins(db)
    elif options.target.lower() == "forms_history":
        if not db:
            db = get_firefox_db("formhistory.sqlite")
        read_moz_forms(db, min_time, max_time)
    elif options.target.lower() == "downloads":
        if not db:
            db = get_firefox_db("downloads.sqlite")
        read_moz_downloads(db, min_time, max_time)