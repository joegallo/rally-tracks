import random
import threading

from esrally import exceptions

async def reindex(es, params):
    source_index = mandatory(params, "source-index", "reindex")
    target_index = mandatory(params, "target-index", "reindex")

    await es.options(request_timeout=300).reindex(
            source={'index': [source_index]},
            dest={'index': target_index},
            refresh=True,
            timeout="300s"
          )

async def put_roles_and_users(es, params):
    for os in ["debian", "redhat", "suse"]:
        await es.security.put_role(
            name=os,
            indices=[
                {
                    'names': [ 'metricbeat*' ],
                    'privileges': [ 'read' ],
                    'query': {
                        'bool': {
                            'must': [
                                { 'term': { 'host.os.family': os } }
                            ]
                        }
                    }
                }
            ]
        )

    for idx, roles in enumerate([
            ["debian"], # user_0
            ["redhat"],
            ["suse"],
            ["debian","redhat"],
            ["debian","suse"],
            ["redhat","suse"],
            ["debian","redhat","suse"] # user_6
    ]):
       await es.security.put_user(
            username="user_" + str(idx),
            password="password",
            roles=roles
        )

counter = 0
lock = threading.Lock()

def get_and_increment():
    global counter
    result = -1
    with lock:
        result = counter
        counter += 1
    return result

queries_and_aggs=[
    [{"bool": {
        "must": [
            {"term": {"metricset.module": "system"}},
            {"term": {"metricset.name": "core"}}
        ]}},
     {"core_system_pct": {
         "percentiles": {"field": "system.core.system.pct"}}}],
    [{"bool": {
        "must": [
            {"term": {"metricset.module": "system"}},
            {"term": {"metricset.name": "network"}}
        ]}},
     {"network_in_bytes": {
         "percentiles": {"field": "system.network.in.bytes"}}}],
    [{"bool": {
        "must": [
            {"term": {"metricset.module": "system"}},
            {"term": {"metricset.name": "process"}}
        ]}},
     {"processor_memory_size": {
         "percentiles": {"field": "system.process.memory.size"}}}],
    [{"bool": {
        "must": [
            {"term": {"metricset.module": "system"}},
            {"term": {"metricset.name": "filesystem"}}
        ]}},
     {"filesystem_free": {
         "percentiles": {"field": "system.filesystem.free"}}}],
    [{"bool": {
        "must": [
            {"term": {"metricset.module": "system"}},
            {"term": {"metricset.name": "memory"}}
        ]}},
     {"memory_total": {
         "percentiles": {"field": "system.memory.total"}}}]
]

async def dls_search(es, params):
    c = get_and_increment()

    # we want some cache cycling, but also some entries that always just stay in the cache, so:
    # 25% of the time, use user_0, 75% of the time, use user_1 through user_6
    uid = random.randint(1, 6)
    if c % 4 == 0:
        uid = 0

    qidx = random.randint(0, 4)
    cost = random.randint(0, 10)

    size = 0
    track_total_hits=False
    query = queries_and_aggs[qidx][0]
    agg = queries_and_aggs[qidx][1]

    if cost == 10:
        size = 100

    if cost >= 3:
        track_total_hits=True

    if cost <= 6:
        agg = None

    await es.options(basic_auth=("user_" + str(uid), "password")).search(
        index="metricbeat*",
        size=size,
        track_total_hits=track_total_hits,
        query=query,
        aggs=agg)

def register(registry):
    registry.register_runner("reindex", reindex, async_runner=True)
    registry.register_runner("put-roles-and-users", put_roles_and_users, async_runner=True)
    registry.register_runner("dls-search", dls_search, async_runner=True)

def mandatory(params, key, op):
    try:
        return params[key]
    except KeyError:
        raise exceptions.DataError(
            f"Parameter source for operation '{str(op)}' did not provide the mandatory parameter '{key}'. "
            f"Add it to your parameter source and try again."
        )
