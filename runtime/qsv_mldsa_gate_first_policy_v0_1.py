"""Pure, no-I/O R4 successor acceptance decision. No pinned modules or disk access.

Consumed by the real gate-first successor entrypoint. A policy verdict is NOT
external approval or a substitute for executing A03. This module tests local
control-flow assertions only, not cryptographic or OS isolation.
"""
from __future__ import annotations

class PolicyBlocked(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)

def require(ok, reason):
    if not ok:
        raise PolicyBlocked(reason)

class _Ticket:
    __slots__ = ('engine', 'lane', 'expected', 'used')
    def __init__(self, engine, lane, expected):
        self.engine, self.lane, self.expected, self.used = engine, lane, expected, False

class _Permit:
    __slots__ = ('engine', 'ticket', 'used')
    def __init__(self, engine, ticket):
        self.engine, self.ticket, self.used = engine, ticket, False

class GateFirstPolicy:
    """One-call state machine; the *caller* must supply only real A03 observations.

    The production successor alone invokes A03 and creates observations.
    Synthetic tests invoke this same class with invented observations.
    These Python tickets are single-use flow guards, NOT cryptographic tokens.
    """
    def __init__(self, expected):
        require(type(expected) is dict and set(expected) ==
                {'prompt_sha256', 'expected_sha256', 'fixture_sha256',
                 'selectors', 'consumer', 'canonical_sha256'}, 'POLICY_EXPECTED_SHAPE')
        self.expected = expected

    def begin(self, lane, *, selectors, consumer, unique_join, canonical_sha256,
              fixture_sha256, collision=False):
        require(lane in ('POSITIVE', 'NEGATIVE_N01'), 'LANE_INVALID')
        require(not collision, 'OUTPUT_COLLISION')
        require(type(selectors) is dict and selectors == self.expected['selectors'], 'SELECTOR_MISMATCH')
        require(type(consumer) is dict and set(consumer) == set(self.expected['consumer']),
                'CONSUMER_11_KEY_SET')
        require(len(consumer) == 11 and all(type(v) is str for v in consumer.values()),
                'CONSUMER_11_TYPES')
        require(consumer == self.expected['consumer'], 'CONSUMER_11_EXACT_MISMATCH')
        require(unique_join == 1, 'HISTORICAL_JOIN_NOT_UNIQUE')
        require(canonical_sha256 == self.expected['canonical_sha256'], 'CANONICAL_MISMATCH')
        require(fixture_sha256 == self.expected['fixture_sha256'], 'FIXTURE_MISMATCH')
        return _Ticket(self, lane, self.expected)

    def after_actual_a03(self, ticket, observation):
        require(type(ticket) is _Ticket and ticket.engine is self and not ticket.used,
                'MISSING_OR_REUSED_ENTRY_TICKET')
        ticket.used = True
        require(type(observation) is dict and set(observation) ==
                {'kind', 'exception_class', 'reason', 'a03_calls', 'a04_calls',
                 'envelope', 'prompt_sha256', 'expected_sha256',
                 'fixture_sha256', 'origin'}, 'A03_OBSERVATION_SHAPE')
        require(observation['origin'] == 'ACTUAL_A03_THIS_ENTRYPOINT',
                'FORGED_OR_CACHED_GATE_NOT_AUTHORITY')
        require(observation['a03_calls'] == 1, 'ACTUAL_A03_CALL_COUNT')
        require(observation['expected_sha256'] == self.expected['expected_sha256'],
                'EXPECTED_RESULTS_SOURCE_DIGEST')
        require(observation['fixture_sha256'] == self.expected['fixture_sha256'],
                'PUBLISHED_FIXTURE_DIGEST')
        if observation['kind'] == 'RAISED':
            require(observation['exception_class'] == 'PreacceptanceBlocked',
                    'WRONG_A03_EXCEPTION_CLASS')
            require(ticket.lane == 'NEGATIVE_N01', 'POSITIVE_UNEXPECTED_REJECT')
            require(observation['reason'] == 'PINNED_SOURCE_DIGEST_MISMATCH',
                    'WRONG_A03_REJECT_REASON')
            require(observation['a04_calls'] == 0, 'A04_REACHED_ON_REJECT')
            require(observation['envelope'] is None, 'REJECT_RETURNED_ENVELOPE')
            require(observation['prompt_sha256'] != self.expected['prompt_sha256'],
                    'NEGATIVE_PROMPT_NOT_MUTATED')
            return ('REJECT', None)
        require(observation['kind'] == 'RETURNED', 'UNKNOWN_GATE_KIND')
        require(ticket.lane == 'POSITIVE', 'MUTATION_UNEXPECTED_A03_PASS')
        require(observation['exception_class'] is None and observation['reason'] is None,
                'PASS_EXCEPTION_MARKERS_PRESENT')
        require(observation['a04_calls'] == 2, 'POSITIVE_A04_REGENERATION_COUNT')
        require(observation['prompt_sha256'] == self.expected['prompt_sha256'],
                'POSITIVE_PROMPT_SOURCE_DIGEST')
        e = observation['envelope']
        require(type(e) is dict and e.get('decision') == 'PREACCEPTANCE_PASS' and
                e.get('acceptance_mode') == 'source_bound', 'A03_PASS_ENVELOPE_REQUIRED')
        sg = e.get('source_regeneration')
        require(type(sg) is dict and sg.get('status') == 'PASS', 'A03_SOURCE_REGEN_STATUS')
        for key in ('requested', 'performed', 'runs_byte_identical',
                    'published_fixture_byte_match', 'same_verified_bytes_consumed'):
            require(sg.get(key) is True, 'A03_REGEN_FIELD_' + key)
        require(sg.get('first_run_digest') == self.expected['fixture_sha256'] and
                sg.get('second_run_digest') == self.expected['fixture_sha256'],
                'A03_REGEN_DIGESTS')
        require(e.get('case_identity') == {k:v for k,v in self.expected['selectors'].items()
                if k != 'implementation_id'}, 'A03_CASE_IDENTITY_MISMATCH')
        sf = e.get('source_files')
        require(type(sf) is list and len(sf) == 2, 'A03_TWO_SOURCE_ROWS')
        observed = {}
        for row in sf:
            require(type(row) is dict and row.get('role') in ('prompt','expected_results')
                    and row['role'] not in observed, 'A03_SOURCE_ROLE_DUPLICATE')
            role = row['role']; pin = self.expected['expected_sha256' if role == 'expected_results' else 'prompt_sha256']
            require(row.get('expected_sha256') == pin and
                    row.get('observed_sha256') == pin and
                    row.get('consumed_sha256') == pin and row.get('digest_match') is True,
                    'A03_CONSUMED_SOURCE_DIGEST_'+role)
            observed[role] = pin
        require(set(observed) == {'prompt','expected_results'}, 'A03_SOURCE_ROLE_SET')
        nb = e.get('normalized_result_source_binding')
        require(type(nb) is dict and nb.get('source_regeneration_performed') is True
                and nb.get('same_verified_bytes_consumed') is True and
                nb.get('pinned_source_digests') == observed and
                nb.get('historical_canonical_sha256') == self.expected['canonical_sha256'],
                'A03_NORMALIZED_SOURCE_BINDING')
        require(e.get('published_fixture',{}).get('sha256') == self.expected['fixture_sha256'],
                'A03_PUBLISHED_FIXTURE_DIGEST')
        return ('ACCEPT', _Permit(self, ticket))

    def consume_construction_permit(self, permit):
        require(type(permit) is _Permit and permit.engine is self and
                permit.ticket.engine is self and permit.ticket.lane == 'POSITIVE' and
                permit.ticket.used and not permit.used, 'UNGATED_OR_REUSED_CONSTRUCTOR')
        permit.used = True
        return True

    def assert_outcomes(self, positive, negative, positive_builder_calls,
                        negative_builder_calls, positive_accepted, negative_accepted):
        require(positive == 'ACCEPT' and negative == 'REJECT', 'TWO_LANE_OUTCOME')
        require(positive_builder_calls == 1 and negative_builder_calls == 0,
                'BUILDER_COUNTS_INVALID')
        require(positive_accepted == 1 and negative_accepted == 0,
                'ACCEPTED_RESULT_COUNTS_INVALID')
        return True
