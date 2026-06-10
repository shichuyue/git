# git
# 隐私流量拦截代理工具
## 项目介绍
基于mitmproxy搭建本地HTTP/HTTPS代理，拦截网页、App埋点SDK，消除设备指纹追踪，属于网络工程作业。

## 技术栈
- Python + mitmproxy 代理核心
- Electron 桌面图形界面
- mitmproxy自动生成CA证书
- Git + GitHub 版本托管

## 运行步骤
1. 安装Python依赖：`pip install mitmproxy`
2. 安装cert目录根证书到系统信任区
3. 启动Electron界面开启代理
4. 系统设置代理地址 127.0.0.1:8080

## 功能清单
1. 黑名单域名拦截广告/统计埋点
2. 随机伪装UA、删除追踪请求头
3. 过滤第三方跨站追踪Cookie
4. 实时流量日志审计
