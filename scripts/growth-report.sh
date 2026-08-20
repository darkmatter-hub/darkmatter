#!/usr/bin/env bash
# Growth report — the honest answer to "is anyone actually using this?"
#
#   bash scripts/growth-report.sh
#
# Reads DATABASE_URL from .env (gitignored). Read-only; changes nothing.
#
# Designed to resist self-flattery. Two lessons are baked in:
#
#  1. Package download counts are dominated by mirrors, CI and bots at low
#     volume. A package nobody uses still shows dozens of pulls a month.
#  2. Raw click counts are no better. The first run of this report classified
#     46 axios/1.13.2 hits as "possible human" because the regex only looked
#     for the word "bot". HTTP libraries, link checkers and preview fetchers
#     all pull a URL without any person seeing the page.
#
# So clicks are counted only from real browser user agents, and signups exclude
# probe and test addresses.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

DB=$(grep -m1 '^DATABASE_URL=' .env 2>/dev/null | cut -d= -f2-)
[ -z "${DB:-}" ] && { echo "ERROR: DATABASE_URL not set in .env" >&2; exit 1; }

PSQL="psql"
command -v psql >/dev/null 2>&1 || {
  for v in 18 17 16 15; do
    cand="/c/Program Files/PostgreSQL/$v/bin/psql.exe"
    [ -x "$cand" ] && PSQL="$cand" && break
  done
}
export PGCONNECT_TIMEOUT=20
q() { "$PSQL" "$DB" -A -t -c "$1" 2>/dev/null | tr -d ' \r'; }

BOTS="bot|crawl|spider|preview|fetch|curl|wget|python|headless|slurp|axios|node-fetch|okhttp|go-http|java/|libwww|httpclient|scrapy|monitor|uptime|facebookexternalhit|Twitterbot|Slackbot|Discordbot"
HUMAN="user_agent ~ '^Mozilla/' AND user_agent !~* '$BOTS'"
REAL="email NOT LIKE '%@healthcheck.invalid' AND email NOT LIKE '%@example.com' AND email NOT LIKE '%@example.invalid' AND email NOT LIKE 'probe%'"

echo ""
echo "  DarkMatter growth report — $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "  ────────────────────────────────────────────────────────────"

echo ""
echo "  DEMAND  (a person had to act for these to be non-zero)"
printf "    browser clicks, 7d           %s\n" "$(q "SELECT count(*) FROM click_events WHERE created_at > now() - interval '7 days' AND $HUMAN;")"
printf "    browser clicks, 30d          %s\n" "$(q "SELECT count(*) FROM click_events WHERE created_at > now() - interval '30 days' AND $HUMAN;")"
printf "    automated hits, 30d          %s   (ignore)\n" "$(q "SELECT count(*) FROM click_events WHERE created_at > now() - interval '30 days' AND NOT ($HUMAN);")"
echo "    by source, 30d (browser only):"
"$PSQL" "$DB" -A -F'   ' -t -c "SELECT '      ' || source, count(*) FROM click_events WHERE created_at > now() - interval '30 days' AND $HUMAN GROUP BY source ORDER BY 2 DESC;" 2>/dev/null
printf "    signups, 7d  (excl. probes)  %s\n" "$(q "SELECT count(*) FROM auth.users WHERE created_at > now() - interval '7 days' AND $REAL;")"
printf "    signups, 30d (excl. probes)  %s\n" "$(q "SELECT count(*) FROM auth.users WHERE created_at > now() - interval '30 days' AND $REAL;")"
printf "    total accounts (excl. probes)%s\n" " $(q "SELECT count(*) FROM auth.users WHERE $REAL;")"

echo ""
echo "  USAGE"
printf "    records committed, 7d        %s\n" "$(q "SELECT count(*) FROM commits WHERE timestamp > now() - interval '7 days';")"
printf "    records committed, 30d       %s\n" "$(q "SELECT count(*) FROM commits WHERE timestamp > now() - interval '30 days';")"
printf "    accounts committing, 30d     %s\n" "$(q "SELECT count(DISTINCT a.user_id) FROM commits c JOIN agents a ON a.agent_id=c.from_agent WHERE c.timestamp > now() - interval '30 days';")"
printf "    proofs published (shares)    %s\n" "$(q "SELECT count(*) FROM shared_chains;")"

echo ""
echo "  RETENTION  (the number that decides whether growth is real)"
printf "    accounts active in 2+ weeks  %s\n" "$(q "SELECT count(*) FROM (SELECT a.user_id FROM commits c JOIN agents a ON a.agent_id=c.from_agent GROUP BY a.user_id HAVING count(DISTINCT date_trunc('week', c.timestamp)) >= 2) t;")"

echo ""
echo "  PACKAGE PULLS  (weak signal: mirrors and CI dominate at low volume)"
for p in "@darkmatterhub/mcp-server" "darkmatter-js"; do
  d=$(curl -sS --max-time 15 "https://api.npmjs.org/downloads/point/last-month/$p" 2>/dev/null | sed -n 's/.*"downloads":\([0-9]*\).*/\1/p')
  printf "    %-28s %s / mo\n" "$p" "${d:-n/a}"
done
for p in darkmatter-sdk darkmatter-claude-code; do
  d=$(curl -sS --max-time 15 "https://pypistats.org/api/packages/$p/recent" 2>/dev/null | sed -n 's/.*"last_month":\([0-9]*\).*/\1/p')
  printf "    %-28s %s / mo\n" "$p" "${d:-n/a}"
done

echo ""
echo "  ────────────────────────────────────────────────────────────"
echo "  Package pulls and raw click counts can look healthy while"
echo "  nothing is happening. Browser clicks, non-probe signups and"
echo "  repeat-week accounts are the three that cannot lie."
echo ""
