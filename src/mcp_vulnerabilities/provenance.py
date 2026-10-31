def resolve_provenance_urls(advisory_id: str, aliases: list[str] | None = None) -> dict[str, str]:
    """
    Resolves authoritative source URLs for an advisory ID and its aliases.
    
    Returns a dictionary containing 'osv', and conditionally 'cve', 'nvd', and 'ghsa'.
    """
    urls = {}
    aliases = aliases or []
    all_ids = [advisory_id] + aliases
    
    # OSV is always available
    urls["osv"] = f"https://osv.dev/vulnerability/{advisory_id}"
    
    cve_id = None
    ghsa_id = None
    
    for aid in all_ids:
        if aid.startswith("CVE-") and not cve_id:
            cve_id = aid
        elif aid.startswith("GHSA-") and not ghsa_id:
            ghsa_id = aid
            
    if cve_id:
        urls["cve"] = f"https://www.cve.org/CVERecord?id={cve_id}"
        urls["nvd"] = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        
    if ghsa_id:
        urls["ghsa"] = f"https://github.com/advisories/{ghsa_id}"
        
    return urls

