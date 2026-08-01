"""
ReconEngine: runs scope validation, then fans the four recon checks
and the WHOIS lookup out across a thread pool, then hands everything
to risk assessment and report assembly.
"""

import concurrent.futures
import logging
import config

from modules import domain_info as domain_info_module
from modules import panels as panels_module
from modules import ports as ports_module
from modules import report as report_module
from modules import risk as risk_module
from modules import scope as scope_module
from modules import subdomains as subdomains_module
from modules import techstack as techstack_module
from modules import recommendations

logger = logging.getLogger("ReconGuard.Engine")


class ReconEngine:
    def run_recon(self, raw_domain, authorized=False):
        """
        Returns (success, result). On success, result is the final
        report dict. On failure, result is a human-readable error
        string -- scope failures and mid-scan exceptions both come
        back this way so the Flask layer only has one failure path
        to handle.
        """
        try:
            domain = scope_module.check_scope(raw_domain, authorized=authorized)
        except Exception:
            logger.exception(f"Recon failed for '{domain}'")
            return False, "Recon failed. Check server logs for details."

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=config.MAX_THREADS) as pool:
                sub_future = pool.submit(subdomains_module.enumerate_subdomains, domain)
                port_future = pool.submit(ports_module.scan_ports, domain)
                tech_future = pool.submit(techstack_module.fingerprint, domain)
                panel_future = pool.submit(panels_module.find_panels, domain)
                whois_future = pool.submit(domain_info_module.lookup, domain)

                subdomains = sub_future.result()
                open_ports = port_future.result()
                tech = tech_future.result()
                panels = panel_future.result()
                whois_info = whois_future.result()
        except Exception as exc:
            logger.error(f"Recon failed for '{domain}': {exc}")
            return False, f"Recon failed partway through scanning '{domain}': {exc}"

        risk = risk_module.assess(subdomains, open_ports, tech, panels, whois_info)
        final_report = report_module.build_report(
            domain, subdomains, open_ports, tech, panels, risk, whois_info
        )
        final_report["recommendations"] = recommendations.generate(final_report)

        logger.info(f"Recon complete for '{domain}': risk={risk['rating']} ({risk['score']})")
        return True, final_report


recon_engine = ReconEngine()
