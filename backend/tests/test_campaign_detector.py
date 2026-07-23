from unittest.mock import MagicMock

from app.correlation.campaign_detector import CampaignDetector


def test_campaign_detection_returns_clusters():
    detector = CampaignDetector()

    mock_session = MagicMock()
    mock_driver = MagicMock()

    mock_driver.session.return_value.__enter__.return_value = mock_session

    mock_session.run.return_value = [
        {"seed": "evil.com", "cluster": ["evil.com", "1.1.1.1", "http://evil.com/login"]}
    ]

    detector.driver = mock_driver

    clusters = detector.detect_campaign_candidates()

    assert len(clusters) == 1
    assert clusters[0]["size"] == 3


def test_find_connected_clusters_is_deterministic_given_fixed_input():
    """
    CONTEXT.md §7: "Determinism is a claimed property... test it
    explicitly." Two independent live runs against the real graph were
    compared this session (2026-07-23) and matched exactly -- same
    cluster count, same membership, same list order -- but that live
    check depends on Neo4j actually honoring the query's `ORDER BY
    node.value` across repeated executions, which is not something a
    mocked-driver unit test can verify (a mock trivially returns whatever
    it's told to, in any order). What *is* testable here, and worth
    guarding against regression: given the same rows back from the
    driver, in the same order, find_connected_clusters()'s own
    non-overlapping greedy assignment (visited-set tracking, cluster
    ordering) must be a pure function of that input -- no reliance on
    dict/set iteration order or anything else non-deterministic in the
    Python layer. Calling it twice against the identical mocked response
    must produce identical output, including list order.
    """
    detector = CampaignDetector()

    mock_session = MagicMock()
    mock_driver = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session

    # Multiple seeds, deliberately including overlap (b.com appears in both
    # a.com's and c.com's raw cluster) so the visited-set/non-overlap logic
    # is actually exercised, not just a single trivial cluster.
    fixed_rows = [
        {"seed": "a.com", "cluster": ["a.com", "b.com", "1.1.1.1"]},
        {"seed": "c.com", "cluster": ["c.com", "b.com", "d.com"]},
        {"seed": "e.com", "cluster": ["e.com", "f.com", "g.com"]},
    ]

    mock_session.run.return_value = list(fixed_rows)
    detector.driver = mock_driver
    run1 = detector.find_connected_clusters()

    mock_session.run.return_value = list(fixed_rows)
    run2 = detector.find_connected_clusters()

    assert run1 == run2
    assert len(run1) > 0  # sanity: the fixture actually produces clusters
