from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings("ignore")

index_name = "tmp2"
client = Elasticsearch(f"http://localhost:9200")

function = input("Enter the function name to search : ")


def dfs(function_name, updateMaps_list):

    resp = client.search(index=index_name, pretty=True, source=["called_function_list", "updateMaps"], size=1000, query={
            "bool": {
                "must": {
                    "match_phrase": {
                    "funcName": function_name
                    }
                }
            }
        }).raw["hits"]["hits"][0]["_source"]

    content = resp["called_function_list"]
    updateMaps = resp['updateMaps']
    updateMaps_list += updateMaps
    for func in content:
        dfs(func, updateMaps_list)

WRITTEN_MAPS = []
dfs(function, WRITTEN_MAPS)
print(f"Maps written to throughout the FCG of function {function}")
print(WRITTEN_MAPS)