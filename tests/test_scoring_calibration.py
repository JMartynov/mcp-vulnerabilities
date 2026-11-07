from mcp_vulnerabilities.scoring import CompositeRiskScorer

def test_clean_baseline():
    score = CompositeRiskScorer.calculate_trust_score()
    assert score == 100.0
    tier = CompositeRiskScorer.calculate_trust_tier(score)
    assert tier == "EXCELLENT"

def test_medium_library_cves():
    # 1 medium CVE
    score_1 = CompositeRiskScorer.calculate_trust_score(medium_count=1)
    assert score_1 == 99.5
    assert CompositeRiskScorer.calculate_trust_tier(score_1) == "EXCELLENT"

    # 2 medium CVEs
    score_2 = CompositeRiskScorer.calculate_trust_score(medium_count=2)
    assert score_2 == 99.0
    assert CompositeRiskScorer.calculate_trust_tier(score_2) == "EXCELLENT"

def test_high_library_cves_capped():
    # 20 high unreachable library CVEs => raw penalty = 20 * 2.0 = 40.0
    # But penalty should be capped at 15.0 => score = 100.0 - 15.0 = 85.0
    score = CompositeRiskScorer.calculate_trust_score(critical_high_unreachable_count=20)
    assert score == 85.0
    assert CompositeRiskScorer.calculate_trust_tier(score) == "GOOD"

def test_high_reachable_library_cves_not_capped():
    # 20 high reachable library CVEs => raw penalty = 20 * 2.0 = 40.0
    # Penalty should not be capped => score = 100.0 - 40.0 = 60.0
    score = CompositeRiskScorer.calculate_trust_score(critical_high_count=20)
    assert score == 60.0
    assert CompositeRiskScorer.calculate_trust_tier(score) == "FAIR"

def test_protocol_risk_penalty_dominance():
    # prompt injection penalty 40.0 lowers score appropriately
    score = CompositeRiskScorer.calculate_trust_score(protocol_risk_penalty=40.0)
    assert score == 60.0
    assert CompositeRiskScorer.calculate_trust_tier(score) == "FAIR"
    
    # Combined with capped dependency penalty
    score_combined = CompositeRiskScorer.calculate_trust_score(
        critical_high_unreachable_count=20, # penalty capped at 15.0
        protocol_risk_penalty=40.0
    )
    assert score_combined == 45.0
    assert CompositeRiskScorer.calculate_trust_tier(score_combined) == "RISKY"

def test_trust_tier_transitions():
    assert CompositeRiskScorer.calculate_trust_tier(100.0) == "EXCELLENT"
    assert CompositeRiskScorer.calculate_trust_tier(90.0) == "EXCELLENT"
    
    assert CompositeRiskScorer.calculate_trust_tier(89.9) == "GOOD"
    assert CompositeRiskScorer.calculate_trust_tier(75.0) == "GOOD"
    
    assert CompositeRiskScorer.calculate_trust_tier(74.9) == "FAIR"
    assert CompositeRiskScorer.calculate_trust_tier(50.0) == "FAIR"
    
    assert CompositeRiskScorer.calculate_trust_tier(49.9) == "RISKY"
    assert CompositeRiskScorer.calculate_trust_tier(0.0) == "RISKY"
