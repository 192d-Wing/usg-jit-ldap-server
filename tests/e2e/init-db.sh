#!/bin/sh
# Only create schemas — the LDAP server runs full migrations on startup.
psql -U ldap_test -d ldap_test -c "CREATE SCHEMA IF NOT EXISTS identity;"
psql -U ldap_test -d ldap_test -c "CREATE SCHEMA IF NOT EXISTS runtime;"
