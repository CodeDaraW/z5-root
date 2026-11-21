# vendor · 第三方源码树（不入 git）

体积大（约 780MB），可重新拉取，来源如下。**只作参考，不是构建依赖**
（唯一例外：`kernel-exact` 是读反汇编时对照源码用的，缺了不影响任何脚本运行）。

| 目录 | 来源 | 用途 |
|---|---|---|
| `kernel-exact/` | sonyxperiadev/kernel，分支对应 `32.1.F.1.98` | 结构参考。⚠️ **与设备二进制有加固偏差**：KGSL 的 c70b4f8 补丁设备上是有的、这份源码没有。不要拿它推断设备行为 |
| `kernel-src/` | AOSP 3.10 通用树 | 通用结构参考（`struct cred` 布局、`security_load_policy` 等） |
| `exploit-ref/` | 公开的 CVE-2017-8890 PoC（Nexus 6P / 3.10 / Android 7.x 一批） | 本机化利用的起点参考 |

## 为什么单独放

- git 里放 765MB 的源码树没有任何好处（不可 diff、克隆极慢）。
- 它们的使用方式都是"`grep` 一下某个函数在 3.10 里长什么样"，属于按需查询。

## 重新拉取

```bash
git clone --depth 1 -b <32.1.F.1.98 对应分支> \
    https://github.com/sonyxperiadev/kernel vendor/kernel-exact
```

`exploit-ref/` 是当年从公开渠道取的 PoC 集合，**内容未经审计**。
只在本机、自己的设备上使用。

## 纪律

- 不要把 `vendor/` 里的代码复制进 `analysis/` 或 `apps/`——许可与来源会变得不可追溯。
- 引用时写清"这段逻辑来自 `vendor/kernel-exact/security/selinux/ss/services.c`"，
  并标注"设备二进制是否一致未验证"。
