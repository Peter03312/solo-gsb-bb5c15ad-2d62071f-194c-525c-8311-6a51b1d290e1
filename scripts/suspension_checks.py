"""标准证书临时停用测试：登记/解除/查询、签发拦截（单张+批次+批内引用）、
既有凭据不改写、并发提交次序。

直接压 HTTP 接口（urllib，无第三方依赖）。服务需已启动。
用法: python3 scripts/suspension_checks.py [base_url] [management_key]

依赖：DELIVERY_MANAGEMENT_KEY 默认为 test-admin-key（与其余 *_checks.py 相同，
直接对按默认/测试配置启动的服务运行即可）。
"""
import json
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
MK = sys.argv[2] if len(sys.argv) > 2 else "test-admin-key"
results = []


def call(method, path, body=None, key=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if key is not None:
        headers["X-Management-Key"] = key
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def check(name, cond, detail=""):
    results.append((name, cond, detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + ("" if cond else f" :: {detail}"))


def err_code(body):
    return body.get("error", {}).get("code")


def err_details(body):
    return body.get("error", {}).get("details", {})


TZ = timezone(timedelta(hours=8))
t0 = datetime(2026, 1, 1, 0, 0, tzinfo=TZ)
_seq = [0]


def nxt(prefix):
    _seq[0] += 1
    return f"{prefix}-{_seq[0]}"


def iso(offset_days=0):
    return (t0 + timedelta(days=offset_days)).isoformat()


def ref(no, name=None):
    return call("POST", "/api/v1/reference-certificates", {
        "cert_no": no, "device_id": "DEV-" + no, "device_name": name or ("基准" + no),
        "valid_from": iso(0), "valid_to": iso(1500), "calibrated_at": iso(0)})


def cal(no, parent, conclusion="PASS"):
    return call("POST", "/api/v1/certificates", {
        "cert_no": no, "device_id": "DEV-" + no, "device_name": "仪表" + no,
        "valid_from": iso(2), "valid_to": iso(1200), "calibrated_at": iso(3),
        "conclusion": conclusion, "parent_cert_no": parent})


def make_chain(tag, depth=2):
    """基准 + depth-1 张普通证书链；返回 (基准号, [普通证书号...])。"""
    r = nxt("SR-" + tag)
    check(f"[{tag}] 基准 201", ref(r)[0] == 201)
    cs = []
    prev = r
    for _ in range(depth - 1):
        c = nxt("SC-" + tag)
        check(f"[{tag}] 普通证书 201", cal(c, prev)[0] == 201)
        cs.append(c)
        prev = c
    return r, cs


def suspend(cert_no, reason="期间核查数据存疑，待复核", mkey=MK):
    return call("POST", f"/api/v1/certificates/{cert_no}/suspend",
                {"reason": reason}, key=mkey)


def lift(cert_no, reason="复核合格，恢复使用", mkey=MK):
    return call("POST", f"/api/v1/certificates/{cert_no}/lift-suspension",
                {"reason": reason}, key=mkey)


def suspension_view(cert_no):
    return call("GET", f"/api/v1/certificates/{cert_no}/suspension")


# ---------------------------------------------------------------------------
print("== 0. 前置数据 ==")
r_a, (a1, a2) = make_chain("MAIN", 3)          # 停用主链：r_a -> a1 -> a2
r_b, (b1,) = make_chain("LIFE", 2)             # 生命周期（停用/解除/再停用）
r_c, (c1,) = make_chain("CLEAN", 2)            # 不受影响的干净链
r_old, (old1,) = make_chain("REV", 2)
s, _ = call("POST", f"/api/v1/certificates/{r_old}/revoke", {"reason": "超差"})
check("撤销基准 200（准备非 ACTIVE 证书）", s == 200, f"got {s}")

# ---------------------------------------------------------------------------
print("== A. 登记停用：管理密钥 / 存在性 / 状态 / 原因 ==")
s, e = suspend(r_a, mkey="wrong-admin-key")
check("错误管理密钥 401", s == 401 and err_code(e) == "invalid_management_key", f"{s} {err_code(e)}")
s, e = call("POST", f"/api/v1/certificates/{r_a}/suspend", {"reason": "待复核"})
check("缺少管理密钥头 401", s == 401 and err_code(e) == "invalid_management_key", f"{s} {err_code(e)}")
s, e = suspend("SUSP-NOT-EXIST-xyz")
check("证书不存在 404", s == 404 and err_code(e) == "cert_not_found", f"{s} {err_code(e)}")
s, e = suspend(r_a, reason="   ")
check("停用原因纯空白 422", s == 422 and err_code(e) == "suspension_reason_required", f"{s} {err_code(e)}")
s, e = suspend(r_old)
check("已撤销证书停用 409", s == 409 and err_code(e) == "cert_not_active", f"{s} {err_code(e)}")
s, e = suspend(old1)
check("级联失效证书停用 409", s == 409 and err_code(e) == "cert_not_active", f"{s} {err_code(e)}")

s, body = suspend(r_a)
check("登记停用 201", s == 201, f"got {s} {body}")
sus = body.get("suspension", {})
check("停用记录字段（编号/证书/原因/时刻，未解除）",
      isinstance(sus.get("suspension_id"), int) and sus.get("cert_no") == r_a
      and sus.get("reason") == "期间核查数据存疑，待复核" and bool(sus.get("suspended_at"))
      and sus.get("lifted_at") is None and sus.get("lifted_reason") is None,
      json.dumps(body, ensure_ascii=False))
sus_id_1 = sus.get("suspension_id")

s, e = suspend(r_a)
check("重复停用 409", s == 409 and err_code(e) == "suspension_conflict", f"{s} {err_code(e)}")

# ---------------------------------------------------------------------------
print("== B. 停用期间：单张签发拦截并指出受阻证书与停用源 ==")
s, e = cal(nxt("SB-DIRECT"), r_a)
check("直接引用被停用证书 422", s == 422 and err_code(e) == "reference_suspended", f"{s} {err_code(e)}")
d = err_details(e)
check("详情指出受阻证书与停用源（直接）",
      d.get("parent_cert_no") == r_a and d.get("suspended_cert_no") == r_a
      and bool(d.get("suspended_at")) and bool(d.get("suspension_reason")),
      json.dumps(d, ensure_ascii=False))

s, e = cal(nxt("SB-DOWN"), a1)
check("引用被停用证书的下游 422", s == 422 and err_code(e) == "reference_suspended", f"{s} {err_code(e)}")
d = err_details(e)
check("详情指出受阻证书（下游）与停用源（祖先）",
      d.get("parent_cert_no") == a1 and d.get("suspended_cert_no") == r_a,
      json.dumps(d, ensure_ascii=False))

s, e = cal(nxt("SB-DOWN2"), a2)
check("引用更深层下游同样 422", s == 422 and err_code(e) == "reference_suspended"
      and err_details(e).get("suspended_cert_no") == r_a, f"{s} {err_code(e)}")

s, _ = cal(nxt("SB-CLEAN"), c1)
check("引用未停用链不受影响 201", s == 201, f"got {s}")

s, cur = call("GET", f"/api/v1/certificates/{r_a}")
check("停用不改写证书内容与状态（仍 ACTIVE）",
      s == 200 and cur["status"] == "ACTIVE" and cur["cert_no"] == r_a
      and cur["conclusion"] == "PASS", f"{s} {cur.get('status')}")

# ---------------------------------------------------------------------------
print("== C. 批次签发：批内引用同样拦截，整批不落库 ==")
bk1 = nxt("SUSB-")
s, e = call("POST", "/api/v1/certificate-batches", {
    "batch_key": bk1,
    "certificates": [
        {"kind": "REFERENCE", "cert_no": nxt("SBR-"), "device_id": "DEV-SBR-1",
         "valid_from": iso(0), "valid_to": iso(1500), "calibrated_at": iso(0)},
        {"kind": "CALIBRATION", "cert_no": nxt("SBC-"), "device_id": "DEV-SBC-1",
         "parent_cert_no": a1, "valid_from": iso(2), "valid_to": iso(1200),
         "calibrated_at": iso(3), "conclusion": "PASS"},
    ]})
check("批次引用被停用链下游 422", s == 422 and err_code(e) == "reference_suspended", f"{s} {err_code(e)}")
d = err_details(e)
check("批次错误定位出错编号并指出停用源",
      d.get("cert_no", "").startswith("SBC-") and d.get("suspended_cert_no") == r_a,
      json.dumps(d, ensure_ascii=False))
s, _ = call("GET", f"/api/v1/certificate-batches/{bk1}")
check("被拒批次整批不落库（批次查询 404）", s == 404, f"got {s}")
s, _ = call("GET", f"/api/v1/certificates/{d.get('cert_no')}")
check("被拒批次内证书未落库", s == 404, f"got {s}")

# 批内传递引用：批内证书引用批内证书，间接受阻于库内停用链
bk2 = nxt("SUSB-")
in_a, in_b = nxt("SBI-A"), nxt("SBI-B")
s, e = call("POST", "/api/v1/certificate-batches", {
    "batch_key": bk2,
    "certificates": [
        {"kind": "CALIBRATION", "cert_no": in_b, "device_id": "DEV-SBI-B",
         "parent_cert_no": in_a, "valid_from": iso(2), "valid_to": iso(1200),
         "calibrated_at": iso(3), "conclusion": "PASS"},
        {"kind": "CALIBRATION", "cert_no": in_a, "device_id": "DEV-SBI-A",
         "parent_cert_no": a2, "valid_from": iso(2), "valid_to": iso(1200),
         "calibrated_at": iso(3), "conclusion": "PASS"},
    ]})
check("批内传递引用命中停用 422", s == 422 and err_code(e) == "reference_suspended", f"{s} {err_code(e)}")
check("批内传递引用定位到直接引用受阻链的条目",
      err_details(e).get("cert_no") == in_a
      and err_details(e).get("suspended_cert_no") == r_a,
      json.dumps(err_details(e), ensure_ascii=False))
s, _ = call("GET", f"/api/v1/certificates/{in_b}")
check("批内传递引用被拒后整批不落库", s == 404, f"got {s}")

# 干净批次可正常签发；随后停用其成员，同键重放仍返回首次快照
bk3 = nxt("SUSB-")
ok_ref, ok_cal = nxt("SBK-R"), nxt("SBK-C")
s, first = call("POST", "/api/v1/certificate-batches", {
    "batch_key": bk3,
    "certificates": [
        {"kind": "REFERENCE", "cert_no": ok_ref, "device_id": "DEV-" + ok_ref,
         "valid_from": iso(0), "valid_to": iso(1500), "calibrated_at": iso(0)},
        {"kind": "CALIBRATION", "cert_no": ok_cal, "device_id": "DEV-" + ok_cal,
         "parent_cert_no": ok_ref, "valid_from": iso(2), "valid_to": iso(1200),
         "calibrated_at": iso(3), "conclusion": "PASS"},
    ]})
check("干净批次 201", s == 201, f"got {s}")
s, _ = suspend(ok_ref)
check("停用批次内已签发证书 201", s == 201, f"got {s}")
s, replay = call("POST", "/api/v1/certificate-batches", {
    "batch_key": bk3,
    "certificates": [
        {"kind": "REFERENCE", "cert_no": ok_ref, "device_id": "DEV-" + ok_ref,
         "valid_from": iso(0), "valid_to": iso(1500), "calibrated_at": iso(0)},
        {"kind": "CALIBRATION", "cert_no": ok_cal, "device_id": "DEV-" + ok_cal,
         "parent_cert_no": ok_ref, "valid_from": iso(2), "valid_to": iso(1200),
         "calibrated_at": iso(3), "conclusion": "PASS"},
    ]})
check("停用后同键同内容重试仍 200 且为首次快照", s == 200 and replay == first, f"got {s}")
check("快照内证书状态冻结为 ACTIVE",
      all(it["certificate"]["status"] == "ACTIVE" for it in replay.get("items", [])))
s, e = cal(nxt("SB-AFTER"), ok_cal)
check("但新签发引用该批次证书被拦截 422",
      s == 422 and err_code(e) == "reference_suspended", f"{s} {err_code(e)}")

# ---------------------------------------------------------------------------
print("== D. 解除停用：无生效停用 / 原因 / 密钥 / 解除后恢复 ==")
s, e = lift(r_b, mkey="nope")
check("解除密钥错误 401", s == 401 and err_code(e) == "invalid_management_key", f"{s} {err_code(e)}")
s, e = lift(r_b)
check("无生效停用时解除 409", s == 409 and err_code(e) == "suspension_not_active", f"{s} {err_code(e)}")
s, e = lift("SUSP-NOT-EXIST-xyz")
check("解除不存在证书 404", s == 404 and err_code(e) == "cert_not_found", f"{s} {err_code(e)}")

s, body = suspend(r_b, reason="送检期间暂停溯源")
check("生命周期链登记停用 201", s == 201, f"got {s}")
sus_id_b1 = body["suspension"]["suspension_id"]
s, e = cal(nxt("SL-BLOCK"), b1)
check("停用期间该链签发被拦截", s == 422 and err_code(e) == "reference_suspended", f"{s}")
s, e = lift(r_b, reason="  ")
check("解除原因纯空白 422", s == 422 and err_code(e) == "suspension_reason_required", f"{s} {err_code(e)}")
s, body = lift(r_b)
check("解除停用 200", s == 200, f"got {s} {body}")
sus_b1 = body.get("suspension", {})
check("解除记录回填解除时间与原因",
      sus_b1.get("suspension_id") == sus_id_b1 and bool(sus_b1.get("lifted_at"))
      and sus_b1.get("lifted_reason") == "复核合格，恢复使用",
      json.dumps(body, ensure_ascii=False))
check("解除时刻不早于停用时刻",
      datetime.fromisoformat(sus_b1["lifted_at"]) >= datetime.fromisoformat(sus_b1["suspended_at"]))
s, _ = cal(nxt("SL-OK"), b1)
check("解除后签发恢复 201", s == 201, f"got {s}")
s, e = lift(r_b)
check("重复解除 409", s == 409 and err_code(e) == "suspension_not_active", f"{s} {err_code(e)}")

s, body = suspend(r_b, reason="二次核查")
check("解除后可再次停用 201", s == 201 and body["suspension"]["suspension_id"] != sus_id_b1,
      f"got {s}")
sus_id_b2 = body["suspension"]["suspension_id"]
s, e = cal(nxt("SL-BLOCK2"), b1)
check("再次停用期间签发再次被拦截", s == 422 and err_code(e) == "reference_suspended", f"{s}")
s, _ = lift(r_b, reason="二次复核通过")
check("再次解除 200", s == 200, f"got {s}")

# ---------------------------------------------------------------------------
print("== E. 查询视图：当前状态与历次停用/解除 ==")
s, v = suspension_view(r_b)
hist = v.get("history", [])
check("查询 200 且当前未停用", s == 200 and v["suspended"] is False
      and v["active_suspension"] is None, f"{s} {json.dumps(v, ensure_ascii=False)}")
check("历次停用记录完整（两次，按登记顺序）",
      len(hist) == 2 and hist[0]["suspension_id"] == sus_id_b1
      and hist[1]["suspension_id"] == sus_id_b2,
      json.dumps(hist, ensure_ascii=False))
check("历次记录含停用/解除时间与原因",
      all(h["reason"] and h["suspended_at"] and h["lifted_at"] and h["lifted_reason"]
          for h in hist),
      json.dumps(hist, ensure_ascii=False))

s, v = suspension_view(r_a)
check("生效停用中的视图（suspended=true）",
      s == 200 and v["suspended"] is True
      and v["active_suspension"]["suspension_id"] == sus_id_1
      and v["active_suspension"]["lifted_at"] is None
      and len(v["history"]) == 1, json.dumps(v, ensure_ascii=False))

s, v = suspension_view(c1)
check("从未停用证书：空历史", s == 200 and v["suspended"] is False
      and v["active_suspension"] is None and v["history"] == [], f"{s}")
s, e = suspension_view("SUSP-NOT-EXIST-xyz")
check("查询不存在证书 404", s == 404 and err_code(e) == "cert_not_found", f"{s} {err_code(e)}")

# ---------------------------------------------------------------------------
print("== F. 既有凭据不因停用改写 ==")
# 归档快照：停用链上证书前后完全一致
s, _ = call("POST", "/api/v1/delivery-archives",
            {"archive_no": (arch := nxt("SDA-")), "cert_nos": [c1]})
check("归档包创建 201", s == 201, f"got {s}")
s, before = call("GET", f"/api/v1/delivery-archives/{arch}")
s, _ = suspend(r_c)
check("停用归档链基准 201", s == 201, f"got {s}")
s, after = call("GET", f"/api/v1/delivery-archives/{arch}")
check("已冻结交付快照不因停用改写", s == 200 and after == before)
s, cur = call("GET", f"/api/v1/certificates/{c1}")
check("链上证书内容/状态不因停用改写", cur["status"] == "ACTIVE")
s, _ = lift(r_c)
check("解除归档链停用 200", s == 200, f"got {s}")

# 撤销状态不受停用影响：停用中的证书仍可被撤销，撤销后停用记录保留
s, _ = call("POST", f"/api/v1/certificates/{r_a}/revoke", {"reason": "复核确认超差"})
check("停用中的证书可撤销 200", s == 200, f"got {s}")
s, cur = call("GET", f"/api/v1/certificates/{r_a}")
check("撤销后状态为 REVOKED", cur["status"] == "REVOKED")
s, v = suspension_view(r_a)
check("撤销不改写停用记录（仍生效中）", s == 200 and v["suspended"] is True, f"{s}")
s, e = cal(nxt("SB-REV"), a1)
check("撤销后引用按既有规则拒绝（非停用码）",
      s == 422 and err_code(e) == "reference_not_active", f"{s} {err_code(e)}")

# ---------------------------------------------------------------------------
print("== G. 并发：停用/解除与并发签发按提交次序生效 ==")
# G1: N 条链，停用基准与签发引用其下游同时提交；
# 之后（停用均已提交）再签发必须全部被拦截
N = 8
chains = []
for i in range(N):
    rr, (cc,) = make_chain(f"RACE{i}", 2)
    chains.append((rr, cc, nxt(f"SRACE{i}"), nxt(f"SRACE{i}-AFTER")))
barrier = threading.Barrier(N * 2)
res = {}
rlock = threading.Lock()


def race_suspend(idx, rr):
    barrier.wait()
    s, b = suspend(rr, reason=f"并发停用-{idx}")
    with rlock:
        res[(idx, "sus")] = (s, b.get("error", {}).get("code"))


def race_issue(idx, cc, new_no):
    barrier.wait()
    s, b = cal(new_no, cc)
    with rlock:
        res[(idx, "iss")] = (s, b.get("error", {}).get("code"))


threads = []
for idx, (rr, cc, new_no, _) in enumerate(chains):
    threads.append(threading.Thread(target=race_suspend, args=(idx, rr)))
    threads.append(threading.Thread(target=race_issue, args=(idx, cc, new_no)))
for t in threads:
    t.start()
for t in threads:
    t.join()

n_issued = 0
for idx, (rr, cc, _, _) in enumerate(chains):
    sus_status, sus_code = res[(idx, "sus")]
    check(f"[{idx}] 并发停用登记成功", sus_status == 201, str(res[(idx, "sus")]))
    iss_status, iss_code = res[(idx, "iss")]
    if iss_status == 201:
        n_issued += 1
    else:
        check(f"[{idx}] 签发未抢先则被停用拦截",
              iss_status == 422 and iss_code == "reference_suspended",
              f"{iss_status} {iss_code}")
for idx, (rr, cc, _, after_no) in enumerate(chains):
    s, e = cal(after_no, cc)
    check(f"[{idx}] 停用已提交后签发引用受阻链必被拒",
          s == 422 and err_code(e) == "reference_suspended", f"{s} {err_code(e)}")
print(f"  （并发结果：{n_issued} 张签发先于停用提交而成功，其余被拦截——两类均合法）")

# G2: 同一证书并发停用：恰好 1 个 201，其余 409
r_g2, _ = make_chain("DUP", 1)
M = 5
bar = threading.Barrier(M)
outs = []
olk = threading.Lock()


def dup_suspend(k):
    bar.wait()
    s, b = suspend(r_g2, reason=f"并发重复停用-{k}")
    with olk:
        outs.append((s, b.get("error", {}).get("code")))


ths = [threading.Thread(target=dup_suspend, args=(k,)) for k in range(M)]
for t in ths:
    t.start()
for t in ths:
    t.join()
statuses = sorted(s for s, _ in outs)
check("并发重复停用：1×201 其余 409", statuses == [201] + [409] * (M - 1), str(outs))
check("并发重复停用 409 均为 suspension_conflict",
      all(c == "suspension_conflict" for s, c in outs if s == 409), str(outs))
s, v = suspension_view(r_g2)
check("并发停用后仅一条生效记录", v["suspended"] is True and len(v["history"]) == 1)

# G3: 并发解除：恰好 1 个 200，其余 409
bar = threading.Barrier(M)
louts = []
llk = threading.Lock()


def dup_lift(k):
    bar.wait()
    s, b = lift(r_g2, reason=f"并发解除-{k}")
    with llk:
        louts.append((s, b.get("error", {}).get("code")))


ths = [threading.Thread(target=dup_lift, args=(k,)) for k in range(M)]
for t in ths:
    t.start()
for t in ths:
    t.join()
lstatuses = sorted(s for s, _ in louts)
check("并发解除：1×200 其余 409", lstatuses == [200] + [409] * (M - 1), str(louts))
check("并发解除 409 均为 suspension_not_active",
      all(c == "suspension_not_active" for s, c in louts if s == 409), str(louts))
s, v = suspension_view(r_g2)
check("并发解除后无生效停用", v["suspended"] is False and v["active_suspension"] is None)
check("解除后该链签发恢复", cal(nxt("SLIFT-OK"), r_g2)[0] == 201)

# ---------------------------------------------------------------------------
print("== H. 既有接口契约保持 ==")
s, idx = call("GET", "/")
eps = " ".join(idx.get("endpoints", []))
check("根索引列出新端点", s == 200
      and "/api/v1/certificates/{cert_no}/suspend" in eps
      and "/api/v1/certificates/{cert_no}/lift-suspension" in eps
      and "/api/v1/certificates/{cert_no}/suspension" in eps, eps)
s, _ = call("GET", "/health")
check("健康检查可用", s == 200)

# ---------------------------------------------------------------------------
n_pass = sum(1 for _, ok, _ in results if ok)
n_fail = len(results) - n_pass
print(f"\n结果: PASS={n_pass} FAIL={n_fail}")
sys.exit(1 if n_fail else 0)
