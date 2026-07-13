import unittest

from tinker_delegate.coordination import (
    CollabSession,
    ConsentGrant,
    ConsentDecision,
    CoordinationError,
    CoordinationState,
    Corpus,
    DelegationGrant,
    GateDecision,
    GateResults,
    GatedQuery,
    GrantStatus,
    Participant,
    ParticipantRole,
    RevokeCorpus,
    ReviewerDecision,
    SubmitTurn,
    Turn,
    TurnStatus,
    coordinate,
)


def _session(*, consent=True, delegation=True) -> CollabSession:
    participants = (
        Participant("owner-atlas", ParticipantRole.OWNER),
        Participant("owner-halcyon", ParticipantRole.OWNER),
        Participant("sponsor", ParticipantRole.REQUESTER),
        Participant("cro-agent", ParticipantRole.AGENT, owner_ref="sponsor"),
        Participant("access-officer", ParticipantRole.REVIEWER),
        Participant("ethics-legal", ParticipantRole.REVIEWER),
    )
    corpora = (
        Corpus("corpus://atlas", "owner-atlas", policy_hash="atlas-policy", royalty_per_query=10**9),
        Corpus("corpus://halcyon", "owner-halcyon", policy_hash="halcyon-policy", royalty_per_query=2 * 10**9),
    )
    grants = ()
    if consent:
        grants = (
            ConsentGrant("corpus://atlas", "owner-atlas", "sponsor", "rank", "sft"),
            ConsentGrant("corpus://halcyon", "owner-halcyon", "sponsor", "rank", "sft"),
        )
    delegations = ()
    if delegation:
        delegations = (
            DelegationGrant(
                agent_ref="cro-agent",
                grantor_ref="sponsor",
                corpora=("corpus://atlas", "corpus://halcyon"),
                purposes=("rank",),
                pipelines=("sft",),
            ),
        )
    return CollabSession(
        participants=participants,
        corpora=corpora,
        consent_grants=grants,
        delegation_grants=delegations,
    )


def _turn(turn_id="turn-1", *, purpose="rank", corpora=("corpus://atlas", "corpus://halcyon")) -> Turn:
    return Turn(
        turn_id=turn_id,
        by="cro-agent",
        requester_ref="sponsor",
        purpose=purpose,
        pipeline="sft",
        corpora=corpora,
        requests={corpus_ref: {"purpose": purpose} for corpus_ref in corpora},
    )


def _pass_queries() -> tuple[GatedQuery, ...]:
    return (
        GatedQuery("corpus://atlas", GateDecision.PASS, stage=4, reason="ok"),
        GatedQuery("corpus://halcyon", GateDecision.PASS, stage=4, reason="ok"),
    )


def _quorum_session(*, grant_count=2, quorum="2-of-3") -> CollabSession:
    participants = (
        Participant("owner-atlas", ParticipantRole.OWNER),
        Participant("owner-halcyon", ParticipantRole.OWNER),
        Participant("owner-meridian", ParticipantRole.OWNER),
        Participant("sponsor", ParticipantRole.REQUESTER),
        Participant("cro-agent", ParticipantRole.AGENT, owner_ref="sponsor"),
        Participant("access-officer", ParticipantRole.REVIEWER),
    )
    corpora = (
        Corpus("corpus://atlas", "owner-atlas", policy_hash="atlas-policy", royalty_per_query=10**9),
        Corpus("corpus://halcyon", "owner-halcyon", policy_hash="halcyon-policy", royalty_per_query=2 * 10**9),
        Corpus("corpus://meridian", "owner-meridian", policy_hash="meridian-policy", royalty_per_query=3 * 10**9),
    )
    all_grants = (
        ConsentGrant("corpus://atlas", "owner-atlas", "sponsor", "rank", "sft"),
        ConsentGrant("corpus://halcyon", "owner-halcyon", "sponsor", "rank", "sft"),
        ConsentGrant("corpus://meridian", "owner-meridian", "sponsor", "rank", "sft"),
    )
    return CollabSession(
        participants=participants,
        corpora=corpora,
        consent_grants=all_grants[:grant_count],
        delegation_grants=(
            DelegationGrant(
                agent_ref="cro-agent",
                grantor_ref="sponsor",
                corpora=("corpus://atlas", "corpus://halcyon", "corpus://meridian"),
                purposes=("rank",),
                pipelines=("sft",),
            ),
        ),
        consent_quorum=quorum,
    )


def _quorum_turn(turn_id="quorum-turn") -> Turn:
    return _turn(
        turn_id,
        corpora=("corpus://atlas", "corpus://halcyon", "corpus://meridian"),
    )


def _quorum_pass_queries() -> tuple[GatedQuery, ...]:
    return (
        GatedQuery("corpus://atlas", GateDecision.PASS, stage=4, reason="ok"),
        GatedQuery("corpus://halcyon", GateDecision.PASS, stage=4, reason="ok"),
        GatedQuery("corpus://meridian", GateDecision.PASS, stage=4, reason="ok"),
    )


class CoordinationReducerTest(unittest.TestCase):
    def test_all_pass_with_unanimous_consent_settles_and_meters(self):
        state = CoordinationState(_session())
        state = coordinate(state, SubmitTurn(_turn()))

        state = coordinate(state, GateResults("turn-1", _pass_queries()))

        record = state.turns["turn-1"]
        self.assertEqual(record.status, TurnStatus.SETTLED)
        self.assertEqual(len(record.meters), 2)
        self.assertIsNotNone(record.joint)
        public = record.to_public_dict()
        self.assertEqual(public["raw_secret_egress"], False)
        self.assertNotIn("ok", str(public))
        self.assertNotIn("atlas-policy", str(public))
        self.assertIn("royalty_hash", public["joint"])

    def test_co_owned_corpus_splits_royalty_across_owners(self):
        participants = (
            Participant("owner-atlas", ParticipantRole.OWNER),
            Participant("sponsor", ParticipantRole.REQUESTER),
            Participant("cro-agent", ParticipantRole.AGENT, owner_ref="sponsor"),
        )
        corpora = (
            Corpus(
                "corpus://atlas",
                "owner-atlas",
                policy_hash="atlas-policy",
                royalty_per_query=10**9,
                owner_shares=(("owner-atlas", 7000), ("owner-atlas-2", 3000)),
            ),
        )
        session = CollabSession(
            participants=participants,
            corpora=corpora,
            consent_grants=(ConsentGrant("corpus://atlas", "owner-atlas", "sponsor", "rank", "sft"),),
            delegation_grants=(
                DelegationGrant(
                    agent_ref="cro-agent",
                    grantor_ref="sponsor",
                    corpora=("corpus://atlas",),
                    purposes=("rank",),
                    pipelines=("sft",),
                ),
            ),
        )
        turn = Turn(
            turn_id="turn-1",
            by="cro-agent",
            requester_ref="sponsor",
            purpose="rank",
            pipeline="sft",
            corpora=("corpus://atlas",),
            requests={"corpus://atlas": {"purpose": "rank"}},
        )
        state = coordinate(CoordinationState(session), SubmitTurn(turn))
        state = coordinate(
            state,
            GateResults("turn-1", (GatedQuery("corpus://atlas", GateDecision.PASS, stage=4, reason="ok"),)),
        )
        record = state.turns["turn-1"]
        self.assertEqual(record.status, TurnStatus.SETTLED)
        self.assertEqual(len(record.meters), 2)
        amounts = {m.owner_ref: m.amount for m in record.meters}
        self.assertEqual(amounts["owner-atlas"], 700_000_000)
        self.assertEqual(amounts["owner-atlas-2"], 300_000_000)
        self.assertEqual(sum(m.amount for m in record.meters), 10**9)  # conserved

    def test_corpus_owner_shares_must_sum_to_10000(self):
        with self.assertRaises(CoordinationError):
            Corpus(
                "corpus://atlas",
                "owner-atlas",
                policy_hash="atlas-policy",
                royalty_per_query=10**9,
                owner_shares=(("owner-atlas", 7000), ("owner-atlas-2", 2000)),
            )

    def test_any_deny_denies_without_surface(self):
        state = coordinate(CoordinationState(_session()), SubmitTurn(_turn()))

        state = coordinate(
            state,
            GateResults(
                "turn-1",
                (
                    GatedQuery("corpus://atlas", GateDecision.DENY, stage=1, reason="purpose mismatch"),
                    GatedQuery("corpus://halcyon", GateDecision.PASS, stage=4, reason="ok"),
                ),
            ),
        )

        record = state.turns["turn-1"]
        self.assertEqual(record.status, TurnStatus.DENIED)
        self.assertEqual(record.status_reason, "gate_denied")
        self.assertEqual(record.meters, ())

    def test_restricted_deny_is_terminal_and_consent_cannot_override(self):
        state = coordinate(CoordinationState(_session()), SubmitTurn(_turn(purpose="rank")))

        state = coordinate(
            state,
            GateResults(
                "turn-1",
                (
                    GatedQuery("corpus://atlas", GateDecision.DENY, stage=3, reason="restricted dual-use"),
                    GatedQuery("corpus://halcyon", GateDecision.PASS, stage=4, reason="ok"),
                ),
            ),
        )

        record = state.turns["turn-1"]
        self.assertEqual(record.status, TurnStatus.DENIED)
        self.assertEqual(record.status_reason, "restricted_denied")

    def test_deny_beats_hold_across_corpora(self):
        # Intersection precedence: when one corpus DENIES and another HOLDS, the
        # composed turn must be DENIED (most restrictive wins) — never HELD. If the
        # reducer checked holds before denies, a denied corpus would wrongly
        # proceed to review instead of terminating.
        state = coordinate(CoordinationState(_session()), SubmitTurn(_turn()))
        state = coordinate(
            state,
            GateResults(
                "turn-1",
                (
                    GatedQuery("corpus://atlas", GateDecision.DENY, stage=2, reason="unsupported pipeline"),
                    GatedQuery("corpus://halcyon", GateDecision.HOLD, stage=2, reason="dual-use review"),
                ),
            ),
        )
        record = state.turns["turn-1"]
        self.assertEqual(record.status, TurnStatus.DENIED)
        # No review ticket is opened when the turn is denied outright.
        self.assertEqual(record.tickets, ())

    def test_hold_opens_ticket_agent_cannot_self_approve_and_reviewer_release_regates(self):
        state = coordinate(CoordinationState(_session()), SubmitTurn(_turn()))
        state = coordinate(
            state,
            GateResults(
                "turn-1",
                (
                    GatedQuery("corpus://atlas", GateDecision.HOLD, stage=2, reason="dual-use review"),
                    GatedQuery("corpus://halcyon", GateDecision.PASS, stage=4, reason="ok"),
                ),
            ),
        )
        held = state.turns["turn-1"]
        self.assertEqual(held.status, TurnStatus.HELD)
        self.assertEqual(held.tickets[0].routed_role, "access-review-officer")

        with self.assertRaisesRegex(CoordinationError, "gating turns"):
            coordinate(state, GateResults("turn-1", _pass_queries()))

        self_approved = coordinate(
            state,
            ReviewerDecision(held.tickets[0].ticket_id, "release", reviewer_ref="cro-agent"),
        )
        self.assertEqual(self_approved.turns["turn-1"].status, TurnStatus.DENIED)
        self.assertEqual(self_approved.turns["turn-1"].status_reason, "self_approval_denied")

        released = coordinate(
            state,
            ReviewerDecision(held.tickets[0].ticket_id, "release", reviewer_ref="access-officer"),
        )
        self.assertEqual(released.turns["turn-1"].status, TurnStatus.GATING)
        settled = coordinate(released, GateResults("turn-1", _pass_queries()))
        self.assertEqual(settled.turns["turn-1"].status, TurnStatus.SETTLED)

    def test_missing_consent_withholds_without_meters(self):
        state = coordinate(CoordinationState(_session(consent=False)), SubmitTurn(_turn()))

        state = coordinate(state, GateResults("turn-1", _pass_queries()))

        record = state.turns["turn-1"]
        self.assertEqual(record.status, TurnStatus.AWAITING_CONSENT)
        self.assertEqual(record.status_reason, "missing_consent")
        self.assertEqual(record.meters, ())

    def test_owner_consent_confirmations_settle_after_quorum_is_met(self):
        state = coordinate(CoordinationState(_session(consent=False)), SubmitTurn(_turn()))
        state = coordinate(state, GateResults("turn-1", _pass_queries()))

        state = coordinate(
            state,
            ConsentDecision("turn-1", "corpus://atlas", "owner-atlas", "grant", expires_at=100),
        )

        awaiting = state.turns["turn-1"]
        self.assertEqual(awaiting.status, TurnStatus.AWAITING_CONSENT)
        self.assertEqual(awaiting.status_reason, "missing_consent")
        self.assertEqual(awaiting.meters, ())

        state = coordinate(
            state,
            ConsentDecision("turn-1", "corpus://halcyon", "owner-halcyon", "grant", expires_at=100),
        )

        settled = state.turns["turn-1"]
        self.assertEqual(settled.status, TurnStatus.SETTLED)
        self.assertEqual(settled.status_reason, "settled")
        self.assertEqual(len(settled.meters), 2)
        public = settled.to_public_dict()
        self.assertNotIn("rank", str(public))
        self.assertNotIn("ok", str(public))
        self.assertEqual(public["raw_secret_egress"], False)

    def test_owner_consent_denial_is_terminal(self):
        state = coordinate(CoordinationState(_session(consent=False)), SubmitTurn(_turn()))
        state = coordinate(state, GateResults("turn-1", _pass_queries()))

        state = coordinate(
            state,
            ConsentDecision("turn-1", "corpus://atlas", "owner-atlas", "deny"),
        )

        record = state.turns["turn-1"]
        self.assertEqual(record.status, TurnStatus.DENIED)
        self.assertEqual(record.status_reason, "consent_denied")
        self.assertEqual(record.meters, ())

    def test_consent_confirmation_requires_matching_owner(self):
        state = coordinate(CoordinationState(_session(consent=False)), SubmitTurn(_turn()))
        state = coordinate(state, GateResults("turn-1", _pass_queries()))

        with self.assertRaisesRegex(CoordinationError, "only the corpus owner"):
            coordinate(
                state,
                ConsentDecision("turn-1", "corpus://atlas", "owner-halcyon", "grant"),
            )

        with self.assertRaisesRegex(CoordinationError, "corpus owner"):
            coordinate(
                state,
                ConsentDecision("turn-1", "corpus://atlas", "sponsor", "grant"),
            )

    def test_consent_confirmation_only_applies_to_awaiting_turns(self):
        state = coordinate(CoordinationState(_session()), SubmitTurn(_turn()))

        with self.assertRaisesRegex(CoordinationError, "awaiting-consent"):
            coordinate(
                state,
                ConsentDecision("turn-1", "corpus://atlas", "owner-atlas", "grant"),
            )

    def test_m_of_n_consent_quorum_settles_when_threshold_is_met(self):
        state = coordinate(CoordinationState(_quorum_session(grant_count=2)), SubmitTurn(_quorum_turn()))

        state = coordinate(state, GateResults("quorum-turn", _quorum_pass_queries()))

        record = state.turns["quorum-turn"]
        self.assertEqual(record.status, TurnStatus.SETTLED)
        self.assertEqual(record.status_reason, "settled")
        self.assertEqual(len(record.meters), 3)
        self.assertEqual(record.joint.raw_secret_egress, False)

    def test_m_of_n_consent_quorum_withholds_below_threshold(self):
        state = coordinate(CoordinationState(_quorum_session(grant_count=1)), SubmitTurn(_quorum_turn()))

        state = coordinate(state, GateResults("quorum-turn", _quorum_pass_queries()))

        record = state.turns["quorum-turn"]
        self.assertEqual(record.status, TurnStatus.AWAITING_CONSENT)
        self.assertEqual(record.status_reason, "missing_consent")
        self.assertEqual(record.meters, ())

    def test_invalid_consent_quorum_fails_closed(self):
        for quorum in ("two-of-three", "2-of-4"):
            with self.subTest(quorum=quorum):
                state = coordinate(
                    CoordinationState(_quorum_session(grant_count=3, quorum=quorum)),
                    SubmitTurn(_quorum_turn()),
                )

                state = coordinate(state, GateResults("quorum-turn", _quorum_pass_queries()))

                record = state.turns["quorum-turn"]
                self.assertEqual(record.status, TurnStatus.AWAITING_CONSENT)
                self.assertEqual(record.status_reason, "invalid_consent_quorum")
                self.assertEqual(record.meters, ())

    def test_revocation_fails_in_flight_turns_but_not_settled_turns(self):
        state = CoordinationState(_session())
        state = coordinate(state, SubmitTurn(_turn("settled-turn")))
        state = coordinate(state, GateResults("settled-turn", _pass_queries()))
        state = coordinate(state, SubmitTurn(_turn("in-flight-turn")))

        state = coordinate(state, RevokeCorpus("corpus://halcyon", by="owner-halcyon"))

        self.assertEqual(state.turns["settled-turn"].status, TurnStatus.SETTLED)
        self.assertEqual(state.turns["in-flight-turn"].status, TurnStatus.REVOKED)
        self.assertIn("corpus://halcyon", state.revoked_corpora)

    def test_delegate_exceeds_grantor_scope_is_denied_at_submit(self):
        state = CoordinationState(_session())

        state = coordinate(state, SubmitTurn(_turn(purpose="de-novo-binder-design")))

        record = state.turns["turn-1"]
        self.assertEqual(record.status, TurnStatus.DENIED)
        self.assertEqual(record.status_reason, "delegate_exceeds_scope")

    def test_gate_results_must_cover_exact_corpora(self):
        state = coordinate(CoordinationState(_session()), SubmitTurn(_turn()))

        with self.assertRaisesRegex(CoordinationError, "cover exactly"):
            coordinate(
                state,
                GateResults(
                    "turn-1",
                    (GatedQuery("corpus://atlas", GateDecision.PASS, stage=4),),
                ),
            )


if __name__ == "__main__":
    unittest.main()
