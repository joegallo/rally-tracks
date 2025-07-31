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

async def dls_search(es, params):
    c = get_and_increment()

    # we want some cache cycling, but also some entries that always just stay in the cache, so:
    # 25% of the time, use user_0, 75% of the time, use user_1 through user_6
    uid = random.randint(1, 6)
    if c % 4 == 0:
        uid = 0

    query = random.randint(0, 4)

    if query == 0:
        await es.options(basic_auth=("user_" + str(uid), "password")).search(
            size=0,
            track_total_hits=True,
            index="metricbeat*",
            query={"bool": {
                "must": [
                    {"term": {"metricset.module": "system"}},
                    {"term": {"metricset.name": "core"}}
                ]
            }},
            aggs={"core_system_pct": {
                "percentiles": {"field": "system.core.system.pct"}
            }})
    elif query == 1:
        await es.options(basic_auth=("user_" + str(uid), "password")).search(
            size=0,
            track_total_hits=True,
            index="metricbeat*",
            query={"bool": {
                "must": [
                    {"term": {"metricset.module": "system"}},
                    {"term": {"metricset.name": "network"}}
                ]
            }},
            aggs={"network_in_bytes": {
                "percentiles": {"field": "system.network.in.bytes"}
            }})
    elif query == 2:
        await es.options(basic_auth=("user_" + str(uid), "password")).search(
            size=0,
            track_total_hits=True,
            index="metricbeat*",
            query={"bool": {
                "must": [
                    {"term": {"metricset.module": "system"}},
                    {"term": {"metricset.name": "process"}}
                ]
            }},
            aggs={"processor_memory_size": {
                "percentiles": {"field": "system.process.memory.size"}
            }})
    elif query == 3:
        await es.options(basic_auth=("user_" + str(uid), "password")).search(
            size=0,
            track_total_hits=True,
            index="metricbeat*",
            query={"bool": {
                "must": [
                    {"term": {"metricset.module": "system"}},
                    {"term": {"metricset.name": "filesystem"}}
                ]
            }},
            aggs={"filesystem_free": {
                "percentiles": {"field": "system.filesystem.free"}
            }})
    elif query == 4:
        await es.options(basic_auth=("user_" + str(uid), "password")).search(
            size=0,
            track_total_hits=True,
            index="metricbeat*",
            query={"bool": {
                "must": [
                    {"term": {"metricset.module": "system"}},
                    {"term": {"metricset.name": "memory"}}
                ]
            }},
            aggs={"memory_total": {
                "percentiles": {"field": "system.memory.total"}
            }})
    else:
        raise Exception("Invalid query!")

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
