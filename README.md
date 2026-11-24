# meshcutover

离线、纯 Python 3.12 标准库实现的抽象服务双策略切换隔离验收工具。

- 输入只有服务/节点标签和抽象策略数据，**没有真实地址、不解析 DNS、不发起任何网络连接**。
- 每条候选传输边携带地域、对端证书代号、服务范围和检查节点。
- 路径必须满足边策略、证书信任区、服务范围，以及按指定顺序经过两个不同运维组负责的检查节点。
- 关键业务默认需要两条合规路径，并要求所选路径的内部节点物理故障域互不重叠。
- Audit 在切换前、每批完成后，以及每个声明故障域单独离线时重算路径。
- Plan 对至多 16 个切换组求精确最优：先最小化加权停用时间，再最小化批次数，最后比较规范化批次 ID 序列。
- 全局无解时，对 `protected_businesses` 中每个必保业务分别做一次单独放宽并重解。

## 运行

无需安装第三方依赖。在仓库根目录执行：

```bash
python -m meshcutover audit CASE.json PLAN.json --trace-level compact
python -m meshcutover plan  CASE.json
python -m unittest discover -s tests -v
```

Windows 若使用 Python Launcher：

```powershell
py -3.12 -m meshcutover audit fixtures\transition_case.json fixtures\transition_good_plan.json
py -3.12 -m meshcutover plan fixtures\transition_case.json
py -3.12 -m unittest discover -s tests -v
```

CLI 始终输出 UTF-8 JSON。默认输出缩进 JSON；`--compact` 输出单行 JSON；`--output report.json` 可同时写入 UTF-8 文件。

退出码：

| 退出码 | 含义 |
|---:|---|
| `0` | audit `pass`，或 plan `optimal` / 存在放宽解中的最优解 |
| `1` | audit `fail`，或 plan 严格问题与所有放宽重解均不可满足 |
| `2` | JSON、CASE 或 PLAN 文档/schema 非法 |
| `3` | 未预期内部错误，返回 JSON 错误对象 |

## CLI 形式

题目中的 `audit CASE PLAN` 对应：

```text
python -m meshcutover audit CASE [PLAN]
```

- 提供 `PLAN` 时读取该计划文件。
- 省略 `PLAN` 时，从 `CASE.plan` 读取；若 CASE 顶层本身含 `batches`，也直接作为 PLAN。
- `CASE` 或 `PLAN` 路径可写 `-` 从 stdin 读取（目前 CASE 可用 `-`）。
- `--trace-level full|compact|none` 控制路径轨迹详细程度，默认 `full`。

规划：

```text
python -m meshcutover plan CASE [--no-relax] [--no-audit]
```

## 输入格式：CASE

顶层示例：

```jsonc
{
  "schema": "meshcutover.case.v1",
  "case_id": "example",
  "regions": ["cn-north"],
  "failure_domains": [{"id": "fd1"}, "fd2"],
  "certificates": {
    "cert-a": {"trust_zone": "tz-a"}
  },
  "inspection_groups": ["secops", "netops"],
  "path_policy": {
    "required_paths": 2,
    "failure_required_paths": 2,
    "disjoint_failure_domains": true
  },
  "nodes": [],
  "edges": [],
  "services": [],
  "forbidden_pairs": [],
  "forbidden_group_pairs": [],
  "switch_groups": [],
  "joint_switch_sets": [],
  "batch": {},
  "isolation_operations": [],
  "protected_businesses": [],
  "relaxation": {}
}
```

ID 会做 Unicode NFKC 和 `strip()` 规范化后比较。所有引用必须存在。

### 节点 `nodes[]`

```jsonc
{
  "id": "sec1",                    // 必填
  "kind": "inspection",            // client | service-replica | transport | inspection | ...
  "ops_group": "secops",           // kind=inspection 时必填
  "failure_domain": "fd1",         // 内部/检查节点建议必填；抽象服务端点可省略
  "switch_group": "g1",            // 可选，节点所属原子切换组
  "policy_version": "old",         // 不属于切换组的节点可固定 old/new
  "service_group": "pay"           // 可选，用于 forbidden_group_pairs 展开
}
```

省略 `failure_domain` 的抽象服务标签端点不会因声明故障域离线而被移除；路径内部节点和边注解中的检查节点会收集故障域。

### 候选传输边 `edges[]`

```jsonc
{
  "id": "e1",
  "from": "client",
  "to": "r1",
  "region": "cn-north",                 // 必填；若顶层有 regions，必须已声明
  "peer_cert": "cert-a",                // 必填，必须在 certificates 中
  "cert_zone": "tz-a",                  // 必填，必须等于证书登记的 trust_zone
  "scope": "pay",                       // 或 scopes: ["pay", "refund"]
  "inspection_nodes": ["sec1", "net1"], // 边经过的检查节点，按该边内顺序
  "allowed": {"old": true, "new": false},
  "enabled": true,
  "directed": true
}
```

`allowed` 也可以是布尔值（两个版本相同），或使用 `baseline/candidate`、`v0/v1` 等别名。

也可以用两份策略文档代替边内联结论：

```jsonc
"policies": {
  "old": {
    "default_effect": "deny",
    "edge_effects": {"e1": "allow"},
    "trusted_cert_zones": ["tz-a"]
  },
  "new": {
    "default_effect": "deny",
    "edge_effects": {"e1": "deny"},
    "trusted_cert_zones": ["tz-b"]
  }
}
```

判定边在某个切换状态是否可用时，取两个端点各自策略版本的结论做合取：

```text
edge_authorized =
  decision(version_of(from), edge)
  AND decision(version_of(to), edge)
  AND isolation_allows(edge)
```

因此：

- `old-old` 只取 old 结论；
- `new-new` 只取 new 结论；
- `old-new` 混合状态必须同时满足 old 与 new，常见迁移边会在“只切一边”时中断。

### 检查顺序

顶层或单个 service/forbidden pair 可提供：

```jsonc
"inspection_groups": ["secops", "netops"]
```

表示先遇到第一个运维组的检查节点，再遇到第二个不同运维组的检查节点。也支持显式节点：

```jsonc
"inspection_sequence": [{"node": "sec1"}, {"node": "net1"}]
```

或混合形式：

```jsonc
"inspection_sequence": [{"ops_group": "secops"}, "net1"]
```

访问顺序由两部分合并：

1. 每条边的 `inspection_nodes`（反向遍历双向边时自动反序）；
2. 图路径中 `kind=inspection` 或带 `ops_group` 的目标节点。

### 业务 `services[]`

```jsonc
{
  "id": "checkout",
  "source": "checkout-client",
  "replicas": ["checkout-r1", "checkout-r2"],
  "scope": "checkout",
  "critical": true,
  "required_paths": 2,
  "failure_required_paths": 2,
  "disjoint_failure_domains": true,
  "distinct_replicas": true,
  "require_each_replica": true
}
```

语义：

- 从 `source` 到任一 `replicas/targets` 枚举所有简单路径。
- `required_paths`：正常批后状态至少需要的合规路径数，默认 2。
- `failure_required_paths`：任意一个声明故障域离线后至少需要的路径数。**默认等于 `required_paths`**，即严格保持原路径数；若你的 SLA 是“两条域隔离路径在单域故障后至少活一条”，显式设为 `1`。
- `disjoint_failure_domains=true` 时，必须能选出所需数量且内部故障域两两不相交的路径。
- 给了 `replicas` 时，默认要求每个副本至少一条路径，且选中路径目标副本不同。

### 禁止对 / 禁止组对

显式禁止对使用与业务完全相同的路径定义：

```jsonc
{"id": "deny-retail-pay", "source": "retail", "target": "pay-db", "scope": "pay"}
```

组间禁止可用：

```jsonc
"service_groups": {
  "retail": ["retail-client"],
  "pay": ["pay-r1", "pay-r2"]
},
"forbidden_group_pairs": [
  {"id": "no-retail-to-pay", "source_service_group": "retail",
   "target_service_group": "pay", "scope": "pay"}
]
```

禁止对的要求是在 baseline、每个批后状态、以及单故障域离线轨迹中都不存在合规授权路径。故障域离线只会删路径，不会放行 fail-open。

### 切换组、成组约束和批次额度

```jsonc
"switch_groups": [
  {
    "id": "g1",
    "nodes": ["client"],
    "migration_units": 1,
    "weight": 2,
    "downtime_seconds": 10
  }
],
"joint_switch_sets": [["g1", "g2"]],
"co_switch_node_sets": [["node-a", "node-b"]],
"batch": {
  "capacity": 2,
  "max_batches": 3,
  "windows": [
    {"id": "w1", "capacity": 2},
    {"id": "w2", "capacity": 1}
  ]
}
```

- 同一 `switch_group` 的节点原子切换。
- `joint_switch_sets` 中的组必须出现在同一批；规划器会先用并查集合并为迁移单元。
- `migration_units` 缺省为组内节点数。
- 批次大小为组 `migration_units` 之和，必须小于该批/window/全局容量。
- 声明 `windows` 时，计划必须按声明顺序使用 window id。

### 候选硬隔离操作

```jsonc
"isolation_operations": [
  {
    "id": "iso-edge1",
    "disable_edges": ["bad-edge"],
    "disable_nodes": ["node-x"],
    "disable_failure_domains": ["fd-x"],
    "weight": 10,
    "downtime_seconds": 1
  }
]
```

加权停用成本可直接给：

```jsonc
{"id": "iso1", "weighted_downtime": 7}
```

否则使用 `weight * downtime_seconds`。切换组成本同理。所有组都必须迁移，因此组成本总和是固定下界；操作成本决定主要优化差异。

PLAN 中可在 baseline 前或某批激活，激活后持续有效：

```jsonc
{
  "schema": "meshcutover.plan.v1",
  "initial_isolation_operations": ["iso-edge1"],
  "batches": [
    {
      "id": "b1",
      "window_id": "w1",
      "groups": ["g1", "g2"],
      "isolation_operations": []
    }
  ]
}
```

## Plan 输出与规范化序列

最优输出包含：

```jsonc
"objective": {
  "weighted_downtime": 30,
  "batch_count": 1,
  "switch_group_order": ["g-replicas", "g-source"],
  "canonical_ordinal_sequence": [1, 1],
  "canonical_batch_id_sequence": ["batch-1", "batch-1"],
  "normalized_actual_batch_id_sequence": ["w1", "w1"]
}
```

规范化和比较规则：

1. 切换组按 NFKC/strip 后的 ID 排序；
2. 批次按时间顺序编号为 `1..K`，规范 token 为 `batch-1..batch-K`；
3. 得到每个排序组对应的批次号序列；
4. 先最小化 `weighted_downtime`，再最小化 `batch_count`，最后按整数序列字典序最小化。

规划器使用位掩码 DP/记忆化可行性搜索，严格覆盖至多 16 个切换组。无候选操作或无操作方案已可行时走快速精确路径；存在候选操作时，操作感知 DP 会保留操作激活状态。普通 16 组、容量 8 的全安全图在本机约 0.05 秒完成。

无解时输出：

```jsonc
{
  "status": "infeasible",
  "satisfiable": false,
  "reason_code": "no_safe_batched_transition",
  "message": "...",
  "relaxed_resolves": []
}
```

`reason_code` 还可能是：

- `migration_unit_exceeds_batch_quota`
- `batch_window_count_below_capacity_lower_bound`
- `no_safe_baseline_even_with_all_candidate_operations`
- `final_policy_state_unsafe`

### 单独放宽重解

`protected_businesses` 缺省为所有 critical service。严格问题无解时，对每个必保业务各复制一次 CASE 并只放宽该业务。

默认放宽档 `single_best_effort_path`：

- `required_paths -> 1`
- `failure_required_paths -> 0`
- 关闭该业务的多副本亲和/去重要求

也可配置：

```jsonc
"relaxation": {"type": "waive_disjoint_failure_domains"}
```

或：

```jsonc
"relaxation": {"type": "reduce_required_paths", "by": 1, "minimum": 1}
```

每个重解结果包含自己的状态、目标、计划或不可满足原因。

## Audit 轨迹

Audit 输出的 `checkpoints[]` 包含：

- checkpoint 0：切换前 baseline；
- checkpoint `i>=1`：第 `i` 批完成后；
- `state.switch_group_policy_versions` / `node_policy_versions`；
- `state.edge_states[].endpoint_decisions`：两端 old/new 决策与合取结果；
- 每个业务/禁止对的候选路径数、可用路径、选中的域隔离路径；
- 每个声明故障域离线后的存活路径；
- 每条路径的静态合规检查、动态策略合取、隔离原因和检查节点见证。

首个失败位置在 `first_failure`，例如：

```jsonc
{
  "checkpoint_index": 1,
  "batch_index": 1,
  "batch_id": "b1-only-source-side",
  "phase": "after_batch",
  "reason_code": "insufficient_compliant_paths",
  "request_id": "checkout",
  "domain": null
}
```

## 合成夹具与示例

### 1. 切换前后安全，只切一边失去冗余

文件：

- `fixtures/transition_case.json`
- `fixtures/transition_good_plan.json`
- `fixtures/transition_one_side_bad_plan.json`

```bash
python -m meshcutover audit fixtures/transition_case.json fixtures/transition_good_plan.json --trace-level compact
python -m meshcutover audit fixtures/transition_case.json fixtures/transition_one_side_bad_plan.json --trace-level compact
python -m meshcutover plan fixtures/transition_case.json --no-audit
```

图中有：

- 两条 old-only 路径；
- 两条 new-only 路径；
- 一条 old/new 都允许的 stable 路径。

切换前 old-only + stable 满足三条域隔离路径，因此任意一个内部故障域离线后仍有两条；全量切到 new 后 new-only + stable 同样安全。只切 source 或只切 replicas 时：

- old-only 边遇到 `old AND new=false`；
- new-only 边遇到 `old=false AND new`；
- 只剩 stable 一条路径。

Audit 的首个失败批是 `b1-only-source-side`，原因为 `insufficient_compliant_paths`。

### 2. 本来合规的两条路径共享物理故障域

文件：

- `fixtures/shared_failure_domain_case.json`
- `fixtures/shared_failure_domain_plan.json`

```bash
python -m meshcutover audit fixtures/shared_failure_domain_case.json fixtures/shared_failure_domain_plan.json
```

两条路径的边允许、证书匹配、scope 匹配、secops→netops 顺序也正确，但四个检查节点都在 `fd-shared-rack`。因此正常状态有 2 条可用路径，却选不出域不重叠的一对；`fd-shared-rack` 离线后两条路径都消失。首个违规码为 `no_failure_domain_disjoint_selection`，故障域检查码为 `domain_outage_path_count_below_requirement`。

### 3. 额度导致严格无解，放宽后可分两批

文件：

- `fixtures/strict_infeasible_relaxed_case.json`

```bash
python -m meshcutover plan fixtures/strict_infeasible_relaxed_case.json --no-audit
```

严格二冗余要求 source/replicas 同批，但每批额度为 1，因此严格问题无解。对 `checkout` 做一次单独放宽后，规划器得到两个批次，规范序列为 `[1,2]`。

### 4. 禁止对与候选硬隔离

文件：

- `fixtures/forbidden_isolation_case.json`

```bash
python -m meshcutover plan fixtures/forbidden_isolation_case.json
```

未隔离时禁止对 `deny-rogue-secret` 存在合规路径。候选操作中便宜的 `iso-edge-cheap`（加权停用 7）和昂贵的域隔离（20）都能阻断；规划器选择便宜操作，加上迁移组成本 5，目标值为 12。

## 测试与穷举对拍

`tests/test_parity.py` 构造离线小图，并用独立的 `itertools.permutations` 枚举全部简单路径：

- 对拍引擎路径集合与独立全路径枚举；
- 为每个节点生成独立 switch group，穷举 `2^8=256` 个策略版本状态；
- 对每个状态再穷举 normal + 六个声明故障域离线，共 `256*7` 个状态/故障组合；
- 用独立参考实现计算可用路径数和两路径故障域不相交布尔值，与 `StateEvaluator` 对拍；
- 对至多 3 个切换组穷举所有批次标签分配，与规划器的最少批次和字典序规范序列对拍。

其余 unittest 覆盖夹具、CLI 退出码/JSON 编码、联合切换组和硬隔离选择。

## 设计边界

- 这是抽象验收/规划器，不配置真实网络、不探测证书、不发送流量。
- 路径枚举面向离线小图和可解释轨迹；`limits.max_paths_per_request` 默认 100000，达到上限会返回 `path_enumeration_truncated` 而不是静默判定安全。
- 规划器的主搜索空间是至多 16 个切换组对应的 `2^16` 位掩码；候选操作也以位掩码表示。合成夹具中的操作规模保持较小以便完整轨迹和精确搜索。
