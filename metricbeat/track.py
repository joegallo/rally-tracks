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
            ["debian"],
            ["redhat"],
            ["suse"],
            ["debian","redhat"],
            ["debian","suse"],
            ["redhat","suse"],
            ["debian","redhat","suse"]
    ]):
       await es.security.put_user(
            username="user_" + str(idx),
            password="password",
            roles=roles
        )

def register(registry):
    registry.register_runner("reindex", reindex, async_runner=True)
    registry.register_runner("put-roles-and-users", put_roles_and_users, async_runner=True)

def mandatory(params, key, op):
    try:
        return params[key]
    except KeyError:
        raise exceptions.DataError(
            f"Parameter source for operation '{str(op)}' did not provide the mandatory parameter '{key}'. "
            f"Add it to your parameter source and try again."
        )
