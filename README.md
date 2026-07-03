# recon_discovery
Non-disruptive internal host &amp; service discovery
AUTHORIZED PENETRATION TESTING USE ONLY.
Run only against targets covered by a signed scope / rules of engagement.
 
Design goals (safety-first, "do no harm"):
  * Two staged phases: host discovery -> service discovery on LIVE hosts only.
  * Conservative timing and a hard packet-rate cap so fragile / legacy / OT
    hosts are not overwhelmed.
  * Version detection (-sV) is OFF by default because service probes can crash
    brittle stacks (printers, SCADA, old appliances). It is opt-in and warns.
  * No default NSE scripts (nmap --script) are ever run.
  * Honors an exclude file for out-of-scope or known-fragile hosts.
  * A --fragile mode adds a per-probe scan-delay and lowers the rate further.
  * Everything is logged (exact commands, timestamps, results) as JSON + CSV +
    a human-readable log, suitable for a report appendix / ROE evidence trail.
 
Engine: wraps nmap when present (preferred). Falls back to a rate-limited
pure-python TCP connect scan if nmap is unavailable.
"""
