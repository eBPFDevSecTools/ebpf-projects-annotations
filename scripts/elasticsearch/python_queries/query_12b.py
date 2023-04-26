from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings("ignore")

index_name = "tmp2"
client = Elasticsearch(f"http://localhost:9200")

class DataStruture:
    def __init__(self, funcName=None):
        self.funcName = funcName
        self.children = {}
        self.helper = None


function = input("Enter the function name to search : ")

def dfs(function_name, datastructure):
    datastructure[function_name] = DataStruture(funcName=function_name)
    resp = client.search(index=index_name, pretty=True, source=["called_function_list", "helper"], size=1000, query={
            "bool": {
                "must": {
                    "match_phrase": {
                    "funcName": function_name
                    }
                }
            }
        }).raw["hits"]["hits"][0]["_source"]

    content = resp["called_function_list"]
    datastructure[function_name].helper = resp["helper"]

    for func in content:
        dfs(func, datastructure[function_name].children)

def printFCG(FCG):
    queue = []
    childFuncs = list(FCG.values())
    queue += childFuncs

    while(queue):
        child = queue.pop(0)
        print('Function Name : ', child.funcName)
        print('BPF Helper : ', child.helper)
        queue += list(child.children.values())


FCG = {}
dfs(function, datastructure=FCG)
print(f"FCG of function {function}")
printFCG(FCG)
    