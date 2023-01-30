# Precomputation and updates

Caulk employs a precomputation step in order to make the use of it sublinear in
the group size. This allows neatly separating the membership proof part of
Semacaulk from the nullifier computation, while allowing to blind the
precomputed membership proof differently at each use.

When a group is updated, precomputation is needed again, so there are a few
options as to how to avoid many precomputations in frequently updated groups.
These include storing a history of valid group commitments or batching
insertions and updating the precomputation after some predefined time slot.
This also opens the possibility to use a centralised, but verifiable, service
to compute these for them, since a unique feature of the precomputation in
Caulk is that a batch can be computed even more cheaply. There are, of course,
privacy implications when using a service, but these can also be mitigated
using several techniques and trade-offs.

Additionally, the precomputation done in Caulk is amenable to efficient updates
when the group changes, justifying a higher cost for the initial
precomputation.
