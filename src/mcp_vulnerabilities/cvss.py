import re
import math

def calculate_cvss_v3_score(vector: str) -> float | None:
    match = re.search(r"AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([NLH])/I:([NLH])/A:([NLH])", vector)
    if not match:
        return None
        
    av, ac, pr, ui, s, c, i, a = match.groups()
    
    av_weights = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
    ac_weights = {'L': 0.77, 'H': 0.44}
    pr_weights_U = {'N': 0.85, 'L': 0.62, 'H': 0.27}
    pr_weights_C = {'N': 0.85, 'L': 0.68, 'H': 0.50}
    ui_weights = {'N': 0.85, 'R': 0.62}
    cia_weights = {'N': 0.0, 'L': 0.22, 'H': 0.56}
    
    iss = 1 - ((1 - cia_weights[c]) * (1 - cia_weights[i]) * (1 - cia_weights[a]))
    
    if iss <= 0:
        return 0.0
        
    if s == 'U':
        impact = 6.42 * iss
        exploitability = 8.22 * av_weights[av] * ac_weights[ac] * pr_weights_U[pr] * ui_weights[ui]
        base_score_raw = min(impact + exploitability, 10.0)
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        exploitability = 8.22 * av_weights[av] * ac_weights[ac] * pr_weights_C[pr] * ui_weights[ui]
        base_score_raw = min(1.08 * (impact + exploitability), 10.0)
        
    int_input = round(base_score_raw * 100000)
    if (int_input % 10000) == 0:
        return int_input / 100000.0
    else:
        return (math.floor(int_input / 10000) + 1) / 10.0

def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    else:
        return "UNKNOWN"
