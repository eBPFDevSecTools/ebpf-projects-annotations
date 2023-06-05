from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings("ignore")

index_name = "tmp2"
client = Elasticsearch(f"http://localhost:9200")

class DataStruture:
    def __init__(self, funcName=None):
        self.funcName = funcName
        self.children = {}
        self.comments = {}


function = input("Enter the function name to search : ")

def dfs(function_name, datastructure):
    datastructure[function_name] = DataStruture(funcName=function_name)
    resp = client.search(index=index_name, pretty=True, source=["called_function_list", "humanFuncDescription", "AI_func_description", "developer_inline_comments"], size=1000, query={
            "bool": {
                "must": {
                    "match_phrase": {
                    "funcName": function_name
                    }
                }
            }
        }).raw["hits"]["hits"][0]["_source"]

    content = resp["called_function_list"]
    human_desc = resp["humanFuncDescription"][0]
    if human_desc is not None:
        human_desc = human_desc["description"]
    
    ai_desc = resp["AI_func_description"][0]
    if ai_desc is not None:
        ai_desc = ai_desc["description"]
    
    dev_comms = resp["developer_inline_comments"]

    datastructure[function_name].comments["Human"] = human_desc
    datastructure[function_name].comments["AI"] = ai_desc
    datastructure[function_name].comments["Developer"] = dev_comms

    for func in content:
        dfs(func, datastructure[function_name].children)

def printFCG(FCG):
    queue = []
    childFuncs = list(FCG.values())
    queue += childFuncs

    while(queue):
        child = queue.pop(0)
        print('Function Name : ', child.funcName)
        print('Comments ',child.comments)
        queue += list(child.children.values())


FCG = {}
dfs(function, datastructure=FCG)
print(f"FCG of function {function}")
printFCG(FCG)
    