from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings("ignore")

index_name = "tmp2"
client = Elasticsearch(f"http://localhost:9200")

root_funcs = client.search(index=index_name, pretty=True, source=["funcName"], size=1000, query={
            "match": {
                "is_root_fn": 1
            }
        }).raw["hits"]["hits"]

root_funcs = list(set(map(lambda x: x["_source"]["funcName"], root_funcs)))


def dfs(function_name):
    resp = client.search(index=index_name, pretty=True, source=["called_function_list"], size=1000, query={
            "bool": {
                "must": {
                    "match_phrase": {
                    "funcName": function_name
                    }
                }
            }
        }).raw["hits"]["hits"][0]["_source"]["called_function_list"]

    child = 0
    for func in resp:
        child += dfs(func)
    
    return 1 + child

total_size = 0
for func in root_funcs:
    a = dfs(func)
    total_size += a

total_size /= len(root_funcs)
print(f"Average size of FCGs of all root functions")
print(total_size)