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

def queries_and_aggs(qidx, rand):
    big = rand * 128
    little = rand * 0.125
    if qidx == 0:
        return [
            {
                "bool": {"must": [
                    {"term": {"metricset.module": "system"}},
                    {"term": {"metricset.name": "core"}},
                    {"range" : {"system.core.system.pct" : {"gte" : little}}}
                ]}
            },
            {
                "core_system_pct": {"percentiles": {"field": "system.core.system.pct"}}
            }
        ]
    elif qidx == 1:
        return [
            {
                "bool": {"must": [
                    {"term": {"metricset.module": "system"}},
                    {"term": {"metricset.name": "network"}},
                    {"range" : {"system.network.in.bytes" : {"gte" : big}}}
                ]}
            },
            {
                "network_in_bytes": {"percentiles": {"field": "system.network.in.bytes"}}
            }
        ]
    elif qidx == 2:
        return [
            {
                "bool": {"must": [
                    {"term": {"metricset.module": "system"}},
                    {"term": {"metricset.name": "process"}},
                    {"range" : {"system.process.memory.size" : {"gte" : big}}}
                ]}
            },
            {
                "processor_memory_size": {"percentiles": {"field": "system.process.memory.size"}}
            }
        ]
    elif qidx == 3:
        return [
            {
                "bool": {"must": [
                    {"term": {"metricset.module": "system"}},
                    {"term": {"metricset.name": "filesystem"}},
                    {"range" : {"system.filesystem.free" : {"gte" : big}}}
                ]}
            },
            {
                "filesystem_free": {"percentiles": {"field": "system.filesystem.free"}}
            }
        ]
    elif qidx == 4:
        return [
            {
                "bool": {"must": [
                    {"term": {"metricset.module": "system"}},
                    {"term": {"metricset.name": "memory"}},
                    {"range" : {"system.memory.total" : {"gte" : big}}}
                ]}
            },
            {
                "memory_total": {"percentiles": {"field": "system.memory.total"}}
            }
        ]


async def dls_search(es, params):
    c = get_and_increment()

    # we want some cache cycling, but also some entries that always just stay in the cache, so:
    # 40% of the time, use user_0, 60% of the time, use user_1 through user_6
    uid = random.randint(1, 6)
    if c % 10 <= 4:
        uid = 0

    qidx = random.randint(0, 4)
    filter_value = random.randint(0, 8)
    query, agg = queries_and_aggs(qidx, filter_value)

    cost = random.randint(0, 10)
    size = 0
    track_total_hits=False
    if cost >= 3:
        track_total_hits=True

    if cost <= 6:
        agg = None

    if cost == 10:
        size = 100

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
