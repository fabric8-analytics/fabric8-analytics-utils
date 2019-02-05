"""Various utility functions used across the repo."""

import os
import json
import logging
import datetime
import psycopg2
import psycopg2.extras
from psycopg2 import sql

logger = logging.getLogger(__file__)


class Postgres:
    """Postgres connection session handler."""

    def __init__(self):
        """Initialize the connection to Postgres database."""
        conn_string = "host='{host}' dbname='{dbname}' user='{user}' password='{password}'".\
            format(host=os.getenv('PGBOUNCER_SERVICE_HOST', 'bayesian-pgbouncer'),
                   dbname=os.getenv('POSTGRESQL_DATABASE', 'coreapi'),
                   user=os.getenv('POSTGRESQL_USER', 'coreapi'),
                   password=os.getenv('POSTGRESQL_PASSWORD', 'coreapi'))
        # TODO: Make it a readonly connection or readonly cursor to avoid misuse
        self.conn = psycopg2.connect(conn_string)
        self.cursor = self.conn.cursor()

    def conn(self):
        """Return the established connection."""
        return self.conn

    def cursor(self):
        """Return the established cursor."""
        return self.cursor


pg = Postgres()
conn = pg.conn
cursor = pg.cursor


class ReportHelper:
    """Stack Analyses report helper functions."""

    def validate_and_process_date(self, some_date):
        """Validate the date format and apply the format YYYY-MM-DDTHH:MI:SSZ."""
        try:
            datetime.datetime.strptime(some_date, '%Y-%m-%d')
        except ValueError:
            raise ValueError("Incorrect data format, should be YYYY-MM-DD")
        return some_date

    def retrieve_stack_analyses_ids(self, start_date, end_date):
        """Retrieve results for stack analyses requests."""
        try:
            start_date = self.validate_and_process_date(start_date)
            end_date = self.validate_and_process_date(end_date)
        except ValueError:
            raise "Invalid date format"

        # Avoiding SQL injection
        query = sql.SQL('SELECT {} FROM {} WHERE {}::Date BETWEEN \'%s\' AND \'%s\'').format(
            sql.Identifier('id'), sql.Identifier('stack_analyses_request'),
            sql.Identifier('submitTime')
        )

        cursor.execute(query.as_string(conn) % (start_date, end_date))
        rows = cursor.fetchall()

        id_list = []
        for row in rows:
            for col in row:
                id_list.append(col)

        return id_list

    def retrieve_worker_results(self, id_list=[], worker_list=[]):
        """Retrieve results for selected worker from RDB."""
        result = {}
        # convert the elements of the id_list to sql.Literal
        # so that the SQL query statement contains the IDs within quotes
        id_list = list(map(sql.Literal, id_list))
        ids = sql.SQL(', ').join(id_list).as_string(conn)
        print(ids)

        for worker in worker_list:
            query = sql.SQL('SELECT {} FROM {} WHERE {} IN (%s) AND {} = \'%s\'').format(
                sql.Identifier('task_result'), sql.Identifier('worker_results'),
                sql.Identifier('external_request_id'), sql.Identifier('worker')
            )

            cursor.execute(query.as_string(conn) % (ids, worker))
            data = json.dumps(cursor.fetchall())

            # associate the retrieved data to the worker name
            result[worker] = data

        return result

    def normalize_deps_list(self, deps):
        """Normalize the dependencies dict into a list."""
        normalized_list = []
        for dep in deps:
            normalized_list.append('{package} {version}'.format(package=dep['package'],
                                                                version=dep['version']))
        return normalized_list

    def populate_deps_count(self, deps_count_dict, deps):
        """Populate the dependencies count into a dict."""
        for dep in deps:
            if dep in deps_count_dict:
                deps_count_dict[dep] += 1
            else:
                deps_count_dict[dep] = 1
        return deps_count_dict

    def retrieve_dependencies_count(self, stack_data):
        """Retrieve the dependencies count."""
        deps_count_dict = {}

        for data in json.loads(stack_data):
            try:
                deps = self.normalize_deps_list(data[0]['stack_data'][0]['user_stack_info']['dependencies'])
                deps_count_dict = self.populate_deps_count(deps_count_dict, deps)
            except (IndexError, KeyError) as e:
                print('Error: %r' % e)
                continue
        return deps_count_dict

    def retrieve_unknown_licenses_count(self, stack_data):
        """Retrieve unknown licenses count."""
        unknown_licenses_dict = {
            'count': 0,
            'unknown_licenses': []
        }
        for data in json.loads(stack_data):
            try:
                unknown_lic = data[0]['stack_data'][0]['user_stack_info']['license_analysis']\
                    ['unknown_licenses']['really_unknown']
                for lic in unknown_lic:
                    unknown_licenses_dict['count'] += 1
                    unknown_licenses_dict['unknown_licenses'].append(lic)
            except (IndexError, KeyError) as e:
                print('Error: %r' % e)
                continue
        unknown_licenses_dict['unknown_licenses'] = list(set(unknown_licenses_dict['unknown_licenses']))
        return unknown_licenses_dict

    def retrieve_stack_count_with_lic_conflict(self, stack_data):
        """Retrieve the count of stacks with license conflicts."""
        stack_count_with_lic_conflict = 0
        for data in json.loads(stack_data):
            try:
                if len(data[0]['stack_data'][0]['user_stack_info']['license_analysis']\
                               ['conflict_packages']) > 0:
                    stack_count_with_lic_conflict += 1
            except (IndexError, KeyError) as e:
                print('Error: %r' % e)
                continue
        return stack_count_with_lic_conflict

    def retrieve_stack_count_with_cve(self, stack_data):
        """Retrieve the count of stacks with CVE."""
        stack_count_with_cve = 0
        for data in json.loads(stack_data):
            for pkg in data[0]['stack_data'][0]['user_stack_info']['analyzed_dependencies']\
                    ['conflict_packages']:
                try:
                    if len(pkg['security']) > 0:
                        stack_count_with_cve += 1
                        # breaking as we know that this stack has got CVE
                        break
                except (IndexError, KeyError) as e:
                    print('Error: %r' % e)
                    continue
        return stack_count_with_cve

    def retrieve_unknown_dependencies_list(self, stack_data):
        """Retrieve the list of unknown dependencies."""
        # TODO
        return True




