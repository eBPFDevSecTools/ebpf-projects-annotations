from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings("ignore")

index_name = "tmp2"
client = Elasticsearch(f"http://localhost:9200")

repo = input("Enter the repository name : ")
function = input("Enter the function name to search : ")


def dfs(function_name, call_graph_dict):
    call_graph_dict[function_name] = {}
    resp = client.search(index=index_name, pretty=True, source=["called_function_list"], size=1000, query={
            "bool": {
                "filter": {
                    "match_phrase": {
                    "File": repo
                    }
                },
                "must": {
                    "match_phrase": {
                    "funcName": function_name
                    }
                }
            }
        })
    content = resp.raw["hits"]["hits"][0]["_source"]["called_function_list"]

    for func in content:
        dfs(func, call_graph_dict=call_graph_dict[function_name])

call_graph = {}
dfs(function, call_graph_dict=call_graph)
print(f"Call graph for {function}")
print(call_graph)