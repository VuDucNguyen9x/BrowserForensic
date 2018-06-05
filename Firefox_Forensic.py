#!/usr/bin/env python

import json

try:
    from common_methods import *
except ImportError:
    sys.exit("Could not find common_methods.py... download the full toolkit from https://github.com/VuDucNguyen9x/BrowserForensicr")


def read_moz_cookies(cookies_db):
    '''Read mozilla firefox cookies. Takes one argument: the full path of the cookies sqlite database file'''
    command = "SELECT baseDomain, name, value, host, path, expiry, lastAccessed as last, creationTime as creat, isSecure, isHttpOnly, inBrowserElement, sameSite FROM moz_cookies"
    res = pull_from_db(cookies_db, command)
    data = init_data("firefox_forensic Cookies", len(res)) + init_table_header("./templates/init_firefox_cookies_html.html")

    objects_list = []
    i = 0

    for row in res:
        creation_date = time_decode("firefox", row[7])
        exp_date = time_decode("firefox", row[5])
        last_access_date = time_decode("firefox", row[6])
        if bool(row[8]) == 0:
            Secure = 'No'
        else:
            Secure = 'Yes'
        if bool(row[9]) == 0:
            HttpOnly = 'No'
        else:
            HttpOnly = 'Yes'

        line = "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>" % (row[0], row[3], row[1], row[2], row[4], creation_date) \
               + "<td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (exp_date, last_access_date, Secure, HttpOnly)
        data += line

        # export cookies json format
        d = sqlite3.collections.OrderedDict()
        d['domain'] = row[3]
        if row[5] != 0:
            d['expirationDate'] = row[5]
        d['hostOnly'] = bool(row[10])
        d['httpOnly'] = bool(row[9])
        d['name'] = row[1]
        d['path'] = row[4]
        if row[11] == 0:
            d['sameSite'] = 'no_restriction'
        d['secure'] = bool(row[8])
        if row[5] == 0:
            d['session'] = True
        else:
            d['session'] = False
        d['storeId'] = str(row[10])
        d['value'] = row[2]
        i += 1
        d['id'] = i
        objects_list.append(d)

    export = json.dumps(objects_list, sort_keys=True, indent=4)
    saveResult("firefox_cookies.json", export)

    data += close_table_html()
    saveResult("firefox_cookies.html", data)

def read_moz_history(history_db, tm_min=0, tm_max=9**18, google=False, android=False):
    '''Read mozilla firefox history. Takes 4 argument:
history_db: the full path of the places sqlite database file
tm_min: the minimum visit timestamp, default value is 0
tm_max: the maximum visit timestamp, default value is 10000000000000
google: Look for google searches only? default value is False'''
    command = "SELECT url, visit_date, title, last_visit_date, visit_count FROM moz_places, moz_historyvisits " \
              + "WHERE (visit_count > 0) AND (moz_places.id == moz_historyvisits.place_id) AND (visit_date > %s AND visit_date < %s);" % (tm_min, tm_max)
    if android:
        command = "SELECT url, ddate, title FROM history WHERE (visits > 0)" \
                  + " AND (date > %s AND date < %s);" % (tm_min, tm_max)
        if google:
            command = "SELECT query, date FROM searchhistory WHERE (visits > 0)" \
                  + " AND (date > %s AND date < %s);" % (tm_min, tm_max)
    res = pull_from_db(history_db, command)
    data = init_data("firefox_forensic History", len(res)) + init_table_header("./templates/init_firefox_history_html.html")

    for row in res:
        if google:
            if android:
                search = str(row[0])
                date = str(row[1])
                title = "Search"
            else:
                url = str(row[0])
                date = str(row[1])
                title = str(row[2])
                if "google" in url.lower():
                    r = re.findall(r'q=.*\&', url)
                    if r:
                        search = r[0].split('&')[0]
                        search = search.replace('q=', '').replace('+', ' ')
            if not search == "":
                line = "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (date, title, search)
                data += line
        else:
            visitdate = time_decode("firefox", row[1])
            title = str(row[2])
            if len(title) == 0:
                title = url
            last_visit_date = time_decode("firefox", row[3])
            line = "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (visitdate, last_visit_date, title, row[0], row[4])
            data += line

    data += close_table_html()
    saveResult("firefox_history.html", data)

def read_moz_searches(searches_db):
    command = "SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE (url like '%p=%') or (url like '%q=%')" \
              "or (url like '%query=%') or (url like '%text=%') or (url like '%wd=%')"
    res = pull_from_db(searches_db, command)
    data = init_data("firefox_forensic Searches", len(res)) + init_table_header(
            "./templates/init_firefox_searches.html")

    for row in res:
        line = "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td</tr>" % (str(row[3]), str(row[1]), str(row[0]), str(row[2]))
        data += line

    data += close_table_html()
    saveResult("firefox_searches.html", data)

def read_moz_logins(logins_db):
    f = open(get_firefox_db(logins_db))
    jdata = json.load(f)
    f.close()
    data = init_data("firefox_forensic Searches", len(jdata)) + init_table_header("./templates/init_firefox_logins.html")
    for l in jdata.get("logins"):
        hostname = l.get("hostname")
        usernameField = l.get("usernameField")
        passwordField = l.get("passwordField")
        encryptedUsername = l.get("encryptedUsername")
        encryptedPassword = l.get("encryptedPassword")
        create_date = time_decode("firefox", int(l.get("timeCreated")))
        lastuse_date = time_decode("firefox", int(l.get("timeLastUsed")))
        change_date = time_decode("firefox", int(l.get("timePasswordChanged")))
        timesUsed = l.get("timesUsed")
        line = "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" \
               % (hostname, usernameField, passwordField, encryptedUsername, encryptedPassword, create_date, lastuse_date, change_date, timesUsed)
        data += line

    data += close_table_html()
    saveResult("firefox_logins.html", data)

def read_moz_forms(forms_db, tm_min=0, tm_max=9**18):
    '''Read mozilla firefox forms history. Takes 3 argument:
forms_db: the full path of the form_history sqlite database file
tm_min: the minimum form use timestamp, default value is 0
tm_max: the maximum form use timestamp, default value is 10000000000000'''
    command = "SELECT fieldname, value, timesUsed, firstUsed, " \
              + "lastUsed FROM moz_formhistory WHERE (firstUsed > %s AND firstUsed < %s);" % (tm_min, tm_max)
    res = pull_from_db(forms_db, command)
    data = init_data("firefox_forensic Forms History", len(res)) + init_table_header("./templates/init_firefox_formhistory_html.html")
    for row in res:

        line = "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (str(row[0]), str(row[1]),
                                                                                     str(row[2]), str(row[3]),
                                                                                     str(row[4]))
        data += line

    data += close_table_html()
    saveResult("firefox_formhistory.html", data)

def read_moz_downloads(downloads_db, tm_min=0, tm_max=9**18):
    '''Read mozilla firefox downloads. Takes 3 argument:
forms_db: the full path of the downloads sqlite database file
tm_min: the minimum download timestamp, default value is 0
tm_max: the maximum download timestamp, default value is 10000000000000'''
    command = "SELECT name, source, endTime FROM moz_downloads WHERE (endtime > %s AND endtime < %s);" % (tm_min, tm_max)
    res = pull_from_db(downloads_db, command)
    data = init_data("firefox_forensic Downloads", len(res)) + init_table_header("./templates/init_firefox_downloads_html.html")

    for row in res:
        line = "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (row[0], row[1], row[2])
        data += line

    data += close_table_html()
    saveResult("firefox_downloads.html", data)
