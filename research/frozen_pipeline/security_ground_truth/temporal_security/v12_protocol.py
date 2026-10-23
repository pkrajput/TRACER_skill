"""v12 source-bound contracts with bounded persistent context."""
from .v11_protocol import (STATIC_INVARIANT, bound_read, consumer_review,
                          probe_metadata, probe_use_qualification,
                          register_preloaded_reads, static_invariant,
                          bind_module_import_target, SYSTEM as V11_SYSTEM)

POLICY = 'v12-bounded-context-class-coverage-public-contracts'
SYSTEM = V11_SYSTEM + '''
For a public tag-stripper/HTMLParser entity-preservation contract, inspect the
parser and callbacks themselves; a full application renderer is not required
to demonstrate loss or alteration of entity text. For a form builder that copies
model help_text into Django Field options, that option is a public HTML contract:
review conditional escaping and any explicit allow-HTML policy. You may establish
these intrinsic contracts statically without initializing a database or model
registry. Choice-label helpers still require the real downstream renderer/escaping
evidence; do not double-escape an intermediate label. Class targets count execution
inside their AST span, including methods. A reached target is execution evidence,
not a security label. Use lightweight objects for intrinsic option construction
where possible; do not claim a copied/reimplemented function tests the real target.
The protocol summary records pending hypothesis IDs. Assess those hypotheses
instead of registering the same unassessed idea again. Older feedback may be
compacted; re-read an omitted excerpt before citing it. Complete trajectories and
source hashes remain archived. No hidden benchmark evaluation is available.
'''
