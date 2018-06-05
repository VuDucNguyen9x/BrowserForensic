#!/usr/bin/env python

import win32crypt, json

try:
    from common_methods import *
except ImportError:
    sys.exit(
        "Could not find common_methods.py... download the full toolkit from https://github.com/VuDucNguyen9x/BrowserForensic")

def read_chrome_history(history_db, tm_min=0, tm_max=9**18, host=None):
    command = "SELECT urls.url, title, visit_time, last_visit_time, visit_count FROM urls, visits WHERE (urls.id = visits.id)" \
              + " AND (visit_time > %s AND visit_time < %s);" % (tm_min, tm_max)

    if host:
        command = command[:-1] + " AND (host_key LIKE '%%%s%%');" % host

    res = pull_from_db(history_db, command)
    data = init_data("chrome_forensic History", len(res)) + init_table_header(
        "./templates/init_chrome_history_html.html")

    for row in res:
        visit_time = time_decode("chrome", row[2])
        last_visit_time = time_decode("chrome", row[3])

        line = "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                visit_time, last_visit_time, row[1], row[0], row[4])
        data += line

    data += close_table_html()
    file_name = "chrome_" + getFileName(history_db) + ".html"
    saveResult(file_name, data)

def read_chrome_searches(searches_db):
    command = "SELECT lower_term, urls.url, title, visit_count FROM keyword_search_terms, urls WHERE (urls.id = keyword_search_terms.url_id)"

    res = pull_from_db(searches_db, command)
    data = init_data("chrome_forensic Searches", len(res)) + init_table_header(
        "./templates/init_chrome_searches_html.html")

    for row in res:
        line = "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (row[0], row[2], row[1], row[3])
        data += line

    data += close_table_html()
    saveResult("chrome_searches.html", data)

def read_chrome_downloads(downloads_db, tm_min=0, tm_max=9**18):
    command = "SELECT url, current_path, start_time, end_time, received_bytes, total_bytes, opened, referrer, " \
              + "last_modified, mime_type FROM downloads, downloads_url_chains " \
              + "WHERE (downloads_url_chains.id = downloads.id) AND (start_time/10000000 > %s AND start_time/10000000 < %s);" % (
              tm_min, tm_max)

    res = pull_from_db(downloads_db, command)
    data = init_data("chrome_scanner Downloads", len(res)) + init_table_header("./templates/init_chrome_downloads_html.html")
    open_dict = {"0": "No", "1": "Yes"}

    for row in res:
        start_time = time_decode("chrome", row[2])
        if row[3] > 0:
            end_time = time_decode("chrome", row[3])
        else:
            end_time = "download interrupted"
        try:
            pct = str(round((100 * row[4]) / row[5], 4)) + " %"
        except ZeroDivisionError:
            pct = "Download size is zero"
        opened = open_dict[str(row[6])]

        line = "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>" % (
        start_time, end_time, row[0], row[9], row[7]) \
               + "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (row[1], row[5], pct, opened, row[8])
        data += line

    data += close_table_html()
    saveResult("chrome_downloads.html", data)

def read_chrome_cookies(cookies_db, tm_min=0, tm_max=9**18, host=None):
    command = """SELECT name, host_key, encrypted_value, path, creation_utc, expires_utc, last_access_utc, has_expires, firstpartyonly, is_httponly, is_secure
                FROM cookies
                WHERE (creation_utc > %s AND creation_utc < %s);""" % (tm_min, tm_max)
    if host:
        command = command[:-1] + " AND (host_key LIKE '%%%s%%');" % host

    res = pull_from_db(cookies_db, command)
    data = init_data("chrome_forensic Cookies", len(res)) + init_table_header("./templates/init_chrome_cookies_html.html")
    exp_dict = {"0": "No", "1": "Yes"}

    objects_list = []
    i = 0

    for row in res:
        creation_date = time_decode("chrome", row[4])
        if row[5] != 0:
            exp_date = time_decode("chrome", row[5])
        else:
            exp_date = row[5]
        last_access_date = time_decode("chrome", row[6])
        exp_stat = exp_dict[str(row[7])]
        value = format(win32crypt.CryptUnprotectData(row[2])[1].decode())

        line = "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>" % (row[1], row[0], value, row[3], creation_date) \
               + "<td>%s</td><td>%s</td><td>%s</td></tr>" % (exp_date, last_access_date, exp_stat)
        data += line

        #export cookies json format
        d = sqlite3.collections.OrderedDict()
        d['domain'] = row[1]
        if row[5] != 0:
            d['expirationDate'] = row[5]
        d['hostOnly'] = bool(row[8])
        d['httpOnly'] = bool(row[9])
        d['name'] = row[0]
        d['path'] = row[3]
        d['sameSite'] = 'no_restriction'
        d['secure'] = bool(row[10])
        if row[5] == 0:
            d['session'] = True
        else: d['session'] = False
        d['storeId'] = str(row[8])
        d['value'] = value
        i += 1
        d['id'] = i
        objects_list.append(d)

    export = json.dumps(objects_list, sort_keys=True, indent=4)
    saveResult("chrome_cookies.json", export)

    data += close_table_html()
    file_name = "chrome_" + getFileName(cookies_db) + ".html"
    saveResult(file_name, data)

def read_chrome_logins(logins_db, tm_min=0, tm_max=9**18, domain=None):
    command = "SELECT action_url, username_value, password_value, signon_realm, date_created, times_used, form_data FROM logins " \
              + "WHERE (date_created > %s AND date_created < %s);" % (tm_min, tm_max)
    if domain:
        command = command[:-1] + " AND (signon_realm LIKE '%%%s%%');" % domain

    res = pull_from_db(logins_db, command)
    data = init_data("chrome_forensic Logins", len(res)) + init_table_header("./templates/init_chrome_logins_html.html")

    for row in res:
        creation_date = time_decode("chrome", row[4])
        password = win32crypt.CryptUnprotectData(row[2], None, None, None, 0)[1]
        form_data = row[6].decode("ISO-8859-1")

        line = "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>" % (creation_date, row[3], row[0], row[1]) \
               + "<td>%s</td><td>%s</td><td>%s</td></tr>" % (password.decode("UTF-8"), row[5], form_data)
        data += line

    data += close_table_html()
    saveResult("chrome_logins.html", data)
