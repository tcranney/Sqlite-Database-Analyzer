# -*- coding: utf-8 -*-

import sqlite3
import csv
import os
import argparse
import numpy as np
import time
from datetime import datetime
path = 'Traceresults'


def get_filename():
    """Gets the filename of the database from the command line arguments

        Args:
            Command line arg of database

        Returns:
            args.filename: The file path of the database
        """
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', type=str)
    args = parser.parse_args()
    return args.filename


def setup_connection(filename):
    """Connects to the database specified

            Args:
                filename: File path of the database in question

            Returns:
                conn: Connection to the database
            """
    conn = sqlite3.connect(filename)
    conn.text_factory = sqlite3.OptimizedUnicode
    return conn


def get_seconds_epoch(str_time):
    """Get the seconds from the epoch that this timestamp occurred

               Args:
                   str_time: Timestamp that is to be dissected

               Returns:
                   striped_time_seconds: Returns the total amount of seconds since the epoc from the timestamp
               """
    striped_time = datetime.strptime(str_time, '%Y-%m-%d %H:%M:%S.%f')
    striped_time_seconds = int(striped_time.strftime("%s"))
    return striped_time_seconds


def get_seconds_in_day(time_string):
    """Gets total seconds of timestamp from the start of the day, i.e no month day year included

               Args:
                   time_string: Timestamp that is to be dissected

               Returns:
                   total_seconds: Total seconds since the beginning of the day to the timestamp
               """
    """string_time is only hours minutes seconds (eg:14:34:36)"""
    total_seconds = datetime.strptime(time_string, '%H:%M:%S').second + \
        (datetime.strptime(time_string, '%H:%M:%S').minute*60) + \
        (datetime.strptime(time_string, '%H:%M:%S').hour*60*60)
    return total_seconds


def exec_query(conn, query, filename, column_headers):
    """Executes a sqlite query and writes the results to a csv

                   Args:
                       conn: The connection to the Database
                       query: The sqlite query to be executed
                       filename: the name of the csv to write results to
                       column_headers:heads of the columns in the csv

                   Returns:
                       Written csv with query results
                   """
    c = conn.cursor()
    conn.text_factory = str
    results = c.execute(query)
    conn.close
    with open(os.path.join(path, filename), 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(column_headers)
        writer.writerows(results)


def get_users_average_finish(conn):
    """Returns the average log off time of all the users in the database

                      Args:
                          conn: The connection to the Database

                      Returns:
                         averages: List of average time of logoff of each user
                         standard_deviations:List of the standard deviations of each users logoffs
                         logoffs: List of all of the users log offs
                      """
    c = conn.cursor()
    conn.text_factory = str
    c.execute('SELECT DISTINCT property_value, time(timestamp) FROM SecurityEventLogSummary '
              'WHERE event_task_name ="Logoff" AND property_name="TargetUserName" ORDER BY property_value')
    results = c.fetchall()
    conn.close
    logoffs = {}
    averages = {}
    standard_deviations = {}
    for row in results:
        username, time = row[0], row[1]
        if uname not in logoffs:
            logoffs[username] = [get_seconds_in_day(time)]
        else:
            logoffs[username].append(get_seconds_in_day(time))
    keys = logoffs.keys()
    for key in keys:
        averages[key] = [(sum(logoffs[key]) / len(logoffs[key]))]
        standard_deviations[key] = [np.std(logoffs[key])]
    return averages, standard_deviations, logoffs


def get_users_average_start(conn):
    """Returns the average log off time of all the users in the database

                        Args:
                            conn: The connection to the Database

                        Returns:
                           averages: List of average time of logons of each user
                           standard_deviations:List of the standard deviations of each users logons
                           logoffs: List of all of the users log ons
                        """
    c = conn.cursor()
    conn.text_factory = str
    c.execute('SELECT DISTINCT property_value, time(timestamp) FROM SecurityEventLogSummary '
              'WHERE event_task_name ="Logon" AND property_name="TargetUserName" ORDER BY property_value')
    results = c.fetchall()
    conn.close
    logons = {}
    averages = {}
    standard_deviations = {}
    for row in results:
        username, time = row[0], row[1]
        if username not in logons:
            logons[username] = [get_seconds_in_day(time)]
        else:
            logons[username].append(get_seconds_in_day(time))
    keys = logons.keys()
    for key in keys:
        averages[key] = [(sum(logons[key]) / len(logons[key]))]
        standard_deviations[key] = [np.std(logons[key])]
    return averages, standard_deviations, logons


def get_users_earliest_log_on_time(conn):
    """Gets the earliest logon time in the day ever for each user

                        Args:
                            conn: The connection to the Database

                        Returns:
                           Outputs a csv with each user's earliest logon time
                        """
    c = conn.cursor()
    conn.text_factory = str
    c.execute('SELECT DISTINCT property_value, time(timestamp) FROM SecurityEventLogSummary '
              'WHERE event_task_name ="Logon" AND property_name="TargetUserName" ORDER BY property_value')
    results = c.fetchall()
    conn.close
    logons = {}
    lowest = []
    for row in results:
        username, tim = row[0], row[1]
        if username not in logons:
            logons[username] = [get_seconds_in_day(tim)]
        else:
            logons[username].append(get_seconds_in_day(tim))
    keys = logons.keys()
    for key in keys:
        minimum = min(logons[key])
        timeout = time.strftime('%H:%M:%S', time.gmtime(minimum))
        out = [key, timeout]
        b = conn.cursor()
        b.execute('SELECT DISTINCT property_value,timestamp FROM SecurityEventLogSummary '
                  'WHERE event_task_name ="Logon" AND property_name="TargetUserName"'
                  ' AND property_value = ? AND time(timestamp)= ? ORDER BY property_value', out)
        result = b.fetchone()
        lowest.append(result)

    with open(os.path.join(path, 'Possible_earliest_logons.csv'), 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(lowest)


def latest_in_day_logons(conn):
    """Gets the latest logon time in the day ever for each user

                        Args:
                            conn: The connection to the Database

                        Returns:
                           Outputs a csv with each user's latest logon time
                        """
    c = conn.cursor()
    conn.text_factory = str
    c.execute('SELECT DISTINCT property_value, time(timestamp) FROM SecurityEventLogSummary '
              'WHERE event_task_name ="Logon" AND property_name="TargetUserName" ORDER BY property_value')
    results = c.fetchall()
    conn.close
    logons = {}
    lowest = []
    for row in results:
        username, tim = row[0], row[1]
        if username not in logons:
            logons[username] = [get_seconds_in_day(tim)]
        else:
            logons[username].append(get_seconds_in_day(tim))
    keys = logons.keys()
    for key in keys:
        minimum = max(logons[key])
        timeout = time.strftime('%H:%M:%S', time.gmtime(minimum))
        out = [key, timeout]
        b = conn.cursor()
        b.execute('SELECT DISTINCT property_value,timestamp FROM SecurityEventLogSummary '
                  'WHERE event_task_name ="Logon" AND property_name="TargetUserName"'
                  ' AND property_value = ? AND time(timestamp)= ? ORDER BY property_value', out)
        result = b.fetchone()
        lowest.append(result)

    with open(os.path.join(path, 'Possible_latest_in_day_logons.csv'), 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(lowest)


def last_logon_ever(conn):
    """Gets the last logon ever of a user (if it hasn't been wiped)

                            Args:
                                conn: The connection to the Database

                            Returns:
                               Outputs a csv with each user's last logon ever
                            """
    c = conn.cursor()
    conn.text_factory = str
    outputs = []
    c.execute('SELECT DISTINCT property_value, timestamp FROM SecurityEventLogSummary '
              'WHERE event_task_name ="Logon" AND property_name="TargetUserName" ORDER BY property_value')
    results = c.fetchall()
    conn.close
    logons = {}
    for row in results:
        username, tim = row[0], row[1]
        if username not in logons:
            logons[username] = [get_seconds_epoch(tim)]
        else:
            logons[username].append(get_seconds_epoch(tim))
    keys = logons.keys()
    for key in keys:
        minimum = max(logons[key])
        timeout = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(minimum))
        out = [key, timeout]
        outputs.append(out)
    with open(os.path.join(path, 'Last_Logon_ever.csv'), 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(outputs)


def suspicous_logins(conn):
    """Gets all logons of a user outside a standard deviation of of their average logon time

                            Args:
                                conn: The connection to the Database

                            Returns:
                               Outputs a csv with all logons outside a standard deviation of the average
                            """
    start, standard_deviation, logons = get_users_average_start(conn)
    outputs = []
    keus = logons.keys()
    for user in keus:
        outputs.append(('Username', user, 'Average start', start[user], ' Standard deviations',
                        standard_deviation[user]))
        for log in logons[user]:
            if (log < start[user] - sum(standard_deviation[user])) or \
                    (log > start[user] + sum(standard_deviation[user])):
                timeout = time.strftime('%H:%M:%S', time.gmtime(log))
                out = [user, timeout]
                b = conn.cursor()
                b.execute('SELECT DISTINCT property_value,timestamp FROM SecurityEventLogSummary '
                          'WHERE event_task_name ="Logon" AND property_name="TargetUserName"'
                          ' AND property_value = ? AND time(timestamp)= ? ORDER BY property_value', out)
                result = b.fetchone()
                outputs.append(result)

    with open(os.path.join(path, 'Logons_outside_of_standard.csv'), 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(outputs)


def suspicous_logoffs(conn):
    """Gets all logoffs of a user outside a standard deviation of of their average logon time

                                Args:
                                    conn: The connection to the Database

                                Returns:
                                   Outputs a csv with all logoffs outside a standard deviation of the average
                                """
    end, standard_deviation, logoffs = get_users_average_finish(conn)
    outputs = []
    keus = logoffs.keys()
    for user in keus:
        outputs.append(('Username', user, 'Average Finish', end[user], 'Standard deviation', standard_deviation[user]))
        for log in logoffs[user]:
            if (log < end[user] - sum(standard_deviation[user])) or (log > end[user] + sum(standard_deviation[user])):
                timeout = time.strftime('%H:%M:%S', time.gmtime(log))
                out = [user, timeout]
                b = conn.cursor()
                b.execute('SELECT DISTINCT property_value,timestamp FROM SecurityEventLogSummary '
                          'WHERE event_task_name ="Logoff" AND property_name="TargetUserName" AND property_value = ?'
                          ' AND time(timestamp)= ? ORDER BY property_value', out)
                resul = b.fetchone()
                outputs.append(resul)
    with open(os.path.join(path, 'Logoffs_outside_of_standard.csv'), 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(outputs)


def run_queries(conn):
    """Runs All of the basic sqlite querys that are written below

                                Args:
                                    conn: The connection to the Database

                                Returns:
                                   Outputs csvs of the results of each query
                                """
    if not os.path.exists(path):
        os.makedirs(path)
    exec_query(conn, 'SELECT DISTINCT username,source_addr,destination_addr,operation FROM NetworkSummary'
               ' WHERE operation="Connection attempted." ORDER BY username',
               'ip_connections_per_user.csv', ['username', 'source_addr', 'destination_addr', 'operation'])
    exec_query(conn, 'SELECT DISTINCT  username,process_hash,process_command_line,'
               'count(*) FROM ProcessParentProcessWithUserSummary WHERE process_hash'
               ' IS NOT NULL GROUP BY process_hash ORDER BY COUNT(*)desc, username asc',
               'get_usual_process_hashes_by_user.csv', ['username', 'process_hash', 'process_command_line', 'count(*)'])
    exec_query(conn, 'SELECT DISTINCT process_table_id,process_name,source_port'
               ' FROM NetworkSummary ORDER BY process_table_id,source_port',
               'process_connecting_to_multiple_ports.csv', ['process_table_id', 'process_name', 'source_port'])
    exec_query(conn, 'SELECT username, process_name, COUNT(*) FROM NetworkSummary'
               ' GROUP BY username ORDER BY COUNT(*) DESC LIMIT 100',
               r'top_users_for_net_activity.csv', ['username', 'process_name', 'COUNT(*)'])
    exec_query(conn, 'SELECT property_value, COUNT(*) FROM (SELECT * FROM SecurityEventLogSummary '
               'WHERE event_task_name like "%Logon%") GROUP BY property_value ORDER BY COUNT(*) DESC LIMIT 10',
               'Get_the_top_10_logged_in_users_sorted_by_count.csv', ['property_value', 'COUNT(*)'])
    exec_query(conn, 'SELECT destination_addr, destination_port, COUNT(*) FROM NetworkSummary '
               'GROUP BY destination_addr, destination_port'
               ' ORDER BY COUNT(*) DESC LIMIT 10', 'Top_DEST_IPs_and_PORT_COMBO.csv',
               ['destination_addr', 'destination_port', 'COUNT(*)'])
    exec_query(conn, 'SELECT source_addr, source_port, COUNT(*) FROM NetworkSummary'
               ' GROUP BY source_addr, source_port ORDER BY COUNT(*) DESC LIMIT 10',
               'Top_SRC_IPs_and_PORT_COMBO.csv', ['source_addr', 'source_port', 'COUNT(*)'])
    exec_query(conn, 'SELECT process_name, COUNT(*) FROM NetworkSummary GROUP BY'
               ' process_name ORDER BY COUNT(*) DESC LIMIT 100', 'Top_process_activity.csv',
               ['process_name', 'COUNT(*)'])
    exec_query(conn, 'SELECT username, COUNT(*) FROM FileSummary GROUP BY username ORDER BY COUNT(*) DESC LIMIT 30',
               r'Users_with_the_most_file_activity.csv', ['username', 'COUNT(*)'])
    exec_query(conn, 'SELECT process_name, COUNT(*) FROM FileSummary GROUP BY'
               ' process_name ORDER BY COUNT(*) DESC LIMIT 30',
               'Processes_with_the_most_file_activity.csv', ['process_name', 'COUNT(*)'])
    exec_query(conn, 'SELECT username, process_name, COUNT(*) FROM FileSummary GROUP BY'
               ' username, process_name ORDER BY COUNT(*) DESC LIMIT 100',
               r'Users_and_processes_combo_with_the_most_activity.csv', ['username', 'process_name'])
    exec_query(conn, 'SELECT DISTINCT username, process_name FROM ProcessSummary'
               ' GROUP BY username, process_name ORDER BY COUNT(*) DESC LIMIT 100',
               'Select_all_unique_user_and_process_combos.csv', ['username', 'process_name'])
    exec_query(conn, 'SELECT create_time, process_name, username, process_table_id FROM (SELECT * FROM ProcessSummary'
               ' WHERE process_name LIKE "%\net.exe" OR '
               'process_name LIKE "%\net1.exe" OR process_name LIKE "%\powershell.exe" OR'
               ' process_name LIKE "%\cmd.exe" OR process_name LIKE "%\hostname.exe" OR'
               ' process_name LIKE "%\whoami.exe")'
               ' GROUP BY create_time, process_name, username, process_table_id ORDER BY create_time',
               'Interesting_clusters_of_suspicous_processes.csv',
               ['create_time', 'process_name', 'username', 'process_table_id'])
    exec_query(conn, 'SELECT username, COUNT(*) FROM ProcessSummary '
               'GROUP BY username ORDER BY COUNT(*) DESC LIMIT 30',
               r'top_users_executing_processes.csv', ['username', 'COUNT(*)'])
    exec_query(conn, 'SELECT process_name, source_addr, destination_addr, destination_port, COUNT(*)'
               ' FROM (SELECT * FROM NetworkSummary WHERE destination_port == "80" OR destination_port == "443")'
               ' GROUP BY process_name ORDER BY COUNT(*) DESC LIMIT 10',
               'Top_processes_using_port_80_or_443_with_src_and_dest_IPs.csv',
               ['process_name', 'source_addr', 'destination_addr', 'destination_port', 'COUNT(*)'])
    exec_query(conn, 'SELECT username, COUNT(*) FROM (SELECT * FROM FileSummary '
               'WHERE file NOT LIKE "C:\%" AND operation == "CreateNewFile") '
               'GROUP BY username ORDER BY COUNT(*) DESC LIMIT 30',
               r'Users_creating_new_files_on_alternate_drives.csv', ['username', 'COUNT(*)'])


def main():
    filename = get_filename()
    connection1 = setup_connection(filename)
    run_queries(connection1)
    connection2 = setup_connection(filename)
    suspicous_logins(connection2)
    connection3 = setup_connection(filename)
    suspicous_logoffs(connection3)
    connection4 = setup_connection(filename)
    get_users_earliest_log_on_time(connection4)
    connection5 = setup_connection(filename)
    latest_in_day_logons(connection5)
    connection6 = setup_connection(filename)
    last_logon_ever(connection6)

if __name__ == '__main__':
    main()
