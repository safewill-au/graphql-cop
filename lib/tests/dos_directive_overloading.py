"""Directive overloading tests."""
import re

from lib.utils import graph_query, curlify

# Directive-count ladder. Baseline (0) first, then scale up. Kept bounded so a
# scan does not keep hammering a target that is already falling over; the loop
# also breaks early as soon as it sees a protection or danger signal.
DIRECTIVE_LADDER = (0, 10, 100, 500, 1000)

# A loaded request this many times slower than the N=0 baseline is treated as a
# superlinear blow-up -> no effective directive cap.
SLOW_FACTOR = 10

# Server phrasing that means it explicitly rejected on a directive/complexity
# limit -- i.e. the target IS protected.
LIMIT_SIGNAL = re.compile(
  r'too many directives|directive.*limit|exceeds maximum|'
  r'query complexity|depth limit|maxDirectives',
  re.IGNORECASE
)


def directive_overloading(url, proxy, headers, debug_mode):
  """Check for directive overloading.

  The old check sent 10 repeated *unknown* directives (`@aa@aa...`). That is a
  detection sniff, not an exploit: 10 unknown directives cost nothing, so a
  server with no directive cap still looks fine on wall-clock.

  This repeats a VALID directive (`@skip(if:true)`) an increasing number of
  times. A valid name passes KnownDirectives and forces the server deep into
  duplicate-directive validation (UniqueDirectivesPerLocation), which is
  superlinear in some engines -- cost explodes even though the query is
  ultimately rejected (the work happens *during* validation, before rejection).

  Establishes a baseline at N=0, then compares each N against it and flags
  VULNERABLE (result=True) on a superlinear slowdown, a 5xx under load, or a
  transport failure (timeout/drop). A directive/complexity limit error means
  the target is PROTECTED (result=False).
  """
  res = {
    'result':False,
    'title':'Directive Overloading',
    'description':'Multiple duplicated directives allowed in a query',
    'impact':'Denial of Service - /' + url.rsplit('/', 1)[-1],
    'severity':'HIGH',
    'color': 'red',
    'curl_verify':''
  }

  if debug_mode:
    headers['X-GraphQL-Cop-Test'] = res['title']

  baseline = None
  for n in DIRECTIVE_LADDER:
    directives = '@skip(if:true)' * n
    q = 'query cop { __typename ' + directives + ' }'

    gql_response = graph_query(url, proxies=proxy, headers=headers, payload=q)

    # graph_query returns {} on a transport failure (timeout / connection
    # drop). Under a load probe that is itself a danger signal -- the payload
    # knocked the server over.
    if not hasattr(gql_response, 'status_code'):
      if n > 0:
        res['result'] = True
      break

    res['curl_verify'] = curlify(gql_response)
    elapsed = gql_response.elapsed.total_seconds()
    body = gql_response.text or ''

    # Protection signal: server explicitly rejects on a directive/complexity
    # limit. Skip N=0 -- the baseline control (zero directives) can never
    # legitimately trip a limit, so a match there is a false positive.
    if n > 0 and LIMIT_SIGNAL.search(body):
      res['result'] = False
      break

    # 5xx under load = server-side failure caused by the payload.
    if n > 0 and 500 <= gql_response.status_code < 600:
      res['result'] = True
      break

    # Baseline is the N=0 timing; everything else is judged relative to it.
    if n == 0:
      baseline = elapsed
      continue

    # Superlinear blow-up: this N took SLOW_FACTOR x the baseline.
    if baseline and elapsed > baseline * SLOW_FACTOR:
      res['result'] = True
      break

  return res
