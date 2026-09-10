"""Measure compact MCP inventories in isolated sessions; verify disabled calls fail.

Run after Cargo builds stop. Optional first argument: absolute mcp-devtools binary.
"""
import json, os, subprocess, sys, tempfile
from pathlib import Path
binary=str(Path(sys.argv[1] if len(sys.argv)>1 else 'target/debug/mcp-devtools').resolve())
results=[]
with tempfile.TemporaryDirectory(prefix='mcp-inventory-') as task_home:
    for label, selection, extra in [('empty auto','auto',{}),('GitHub auto','auto',{'GITHUB_TOKEN':'fixture'}),('GitHub + GitLab','github,gitlab',{}),('all','all',{})]:
        task_env={'PATH':os.environ['PATH'],'HOME':task_home,'MCP_ENABLED_VENDORS':selection,'LOG_STDERR':'off',**extra}
        process=subprocess.Popen([binary],cwd=task_home,env=task_env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        messages=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'inventory-probe','version':'1'}}},{'jsonrpc':'2.0','method':'notifications/initialized'},{'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}},{'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'figma_get_file','arguments':{'file':'test'}}}]
        for msg in messages:
            process.stdin.write(json.dumps(msg)+'\n')
        process.stdin.flush()
        seen=set()
        while len(seen)<3:
            line=process.stdout.readline()
            if not line: raise RuntimeError('server stopped')
            response=json.loads(line)
            if response.get('id')==2:
                tools=response['result']['tools']
                results.append({'selection':label,'tools':len(tools),'compactToolsBytes':len(json.dumps(tools,ensure_ascii=False,separators=(',',':')).encode())})
            if response.get('id')==3 and selection!='all':
                assert response['error']['code']==-32602,response
            if response.get('id') in (1,2,3): seen.add(response['id'])
        process.stdin.close()
        process.wait(timeout=10)
print(json.dumps(results,indent=2))
