"""Independent finite exploration. Signed ints encode value (+/-) and view (abs-1)."""
from functools import lru_cache
from itertools import combinations, product
import json

VIEWS = 4
REPORT_SETS = [r for n in (3,4) for r in combinations(range(4),n)]


@lru_cache(None)
def allowed(locks, prepared):
    values = set()
    for senders in REPORT_SETS:
        honest = [locks[r] for r in senders if r<3]
        for byz in (0,*prepared) if 3 in senders else (0,):
            high = max([byz,*honest],key=abs)
            values.update((1,-1) if high==0 else (high//abs(high),))
    return tuple(sorted(values))


def explore():
    # Fourth member can sign both values in both phases, omit messages and
    # present any previously attainable prepare certificate in its view report.
    frontier = {((0,0,0),(),0)}
    levels = []
    for view in range(VIEWS):
        after = set()
        assignments = edges = 0
        for locks,prepared,decision in frontier:
            options = allowed(locks,prepared) if view else (-1,1)
            for votes in product((0,*options),repeat=3):
                assignments += 1
                possible = [v for v in (-1,1) if votes.count(v)+1>=3]
                assert len(possible)<=1, ("conflicting prepares",view,votes)
                if not possible:
                    after.add((locks,prepared,decision))
                    edges += 1
                    continue
                val, = possible
                stamp = (view+1)*val
                for commitments in product((False,True),repeat=3):
                    new = tuple(stamp if c else old for c,old in zip(commitments,locks))
                    decided = val if sum(commitments)+1>=3 else 0
                    assert not (decision and decided and decision!=decided), (view,locks,prepared,votes,commitments)
                    after.add((new,prepared+(stamp,),decision or decided))
                    edges += 1
        levels.append({"view":view,"incoming_states":len(frontier),"prepare_assignments":assignments,
                       "transitions":edges,"successor_states":len(after),
                       "undecided":sum(d==0 for _,_,d in after)})
        frontier = after
    return {"replicas":4,"quorum":3,"max_faulty":1,"values":2,"heights":1,"views":VIEWS,
            "within_view_prepare_conflicts":0,"conflicting_decisions":0,"levels":levels}


if __name__=="__main__":
    print(json.dumps(explore(),indent=2))
