"""Deadline-bounded HTTP transport; model payload and server streaming unchanged.

The child records the generation header before reading the body. Killing the
child closes our connection but does not establish that the provider billed zero.
"""
import json,subprocess,sys,time
from pathlib import Path
import requests

class Reply:
    def __init__(self,status_code,text,headers):
        self.status_code=status_code;self.text=text;self.headers=headers
    def json(self):return json.loads(self.text)

def _write(path,data):
    p=Path(path);tmp=p.with_suffix('.writing');tmp.write_text(json.dumps(data));tmp.replace(p)

def bounded_post(url,*,headers,data,timeout,artifact_dir,request_id):
    folder=Path(artifact_dir)/'http';folder.mkdir(exist_ok=True)
    meta_path=folder/(request_id+'.json');body_path=folder/(request_id+'.body')
    # timeout is an absolute elapsed-time budget, not a socket inactivity budget.
    duration=float(timeout);started=time.time()
    process=subprocess.Popen([sys.executable,__file__,'--worker',url,str(meta_path),str(body_path),str(duration)],
        stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    timed_out=False
    payload=json.dumps({'headers':headers,'data':data}).encode()
    deadline=started+duration
    while True:
        remaining=deadline-time.time()
        if remaining<=0:
            timed_out=True;process.kill();process.wait(timeout=5);break
        try:
            process.communicate(payload,timeout=min(5.0,remaining))
            break
        except subprocess.TimeoutExpired:
            payload=None  # communicate retains its partially written input buffer

    meta=json.loads(meta_path.read_text()) if meta_path.exists() else {}
    meta.update(client_elapsed_seconds=time.time()-started,client_deadline_exceeded=timed_out,child_exit_code=process.returncode)
    _write(meta_path,meta)
    if timed_out or meta.get('error_type'):
        kind='ReadTimeout' if timed_out else meta['error_type']
        cls=requests.exceptions.ConnectTimeout if kind=='ConnectTimeout' else requests.exceptions.ReadTimeout if kind=='ReadTimeout' else requests.exceptions.ConnectionError
        error=cls('Bounded HTTP transport: '+kind)
        error.generation_id=meta.get('generation_id');error.transport_metadata_path=str(meta_path)
        raise error
    if process.returncode or not body_path.exists():
        error=requests.exceptions.ConnectionError('HTTP worker exited without a complete response')
        error.generation_id=meta.get('generation_id');error.transport_metadata_path=str(meta_path)
        raise error
    return Reply(meta['status_code'],body_path.read_text(),meta.get('response_headers',{}))

def worker():
    url,meta_path,body_path,duration=sys.argv[2:];duration=float(duration)
    supplied=json.loads(sys.stdin.buffer.read());meta={'started_at':time.time()}
    _write(meta_path,meta)
    try:
        with requests.post(url,headers=supplied['headers'],data=supplied['data'],stream=True,
                           timeout=(min(30,duration),min(600,duration))) as response:
            meta.update(status_code=response.status_code,generation_id=response.headers.get('X-Generation-Id'),
                response_headers={k:v for k,v in response.headers.items() if k.lower() in ('x-generation-id','content-type')},headers_at=time.time())
            _write(meta_path,meta)
            with open(body_path,'wb') as f:
                for chunk in response.iter_content(chunk_size=4096):f.write(chunk);f.flush()
            meta['body_complete']=True;meta['completed_at']=time.time();_write(meta_path,meta)
    except Exception as e:
        meta['error_type']=type(e).__name__;meta['completed_at']=time.time();_write(meta_path,meta)
        raise SystemExit(2)

if __name__=='__main__':worker()
