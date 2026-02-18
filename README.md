# PRTSTRIKE - Light Small Quick

![Go Version](https://img.shields.io/badge/Go-1.25.5-00ADD8?style=for-the-badge&logo=go)
![HTML5](https://img.shields.io/badge/html5-%23E34F26.svg?style=for-the-badge&logo=html5&logoColor=white)
![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E)
![CSS3](https://img.shields.io/badge/css3-%231572B6.svg?style=for-the-badge&logo=css3&logoColor=white)
![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge)


***Note：请务必完整看完此README.md再使用本工具。***

![](./readme/demo.gif)

## 0x01 Introduction

PRTSTRIKE，一个轻便、小巧、快捷的轻量化C&C框架，由**Go**编写，最快可**1分钟**部署完成。Build后大小仅**30MB**，***截止2026.2.18，微步0检出***。

## 0x02 Quick Start

部署命令：
```Bash
git clone https://github.com/Team-intN18-SoybeanSeclab/prtstrike.git

cd prtstrike

go run .
```

目前，本工具支持如下功能：
1. 隧道
2. 屏幕截图
3. 文件浏览器
4. 生成Shellcode，EXE，ELF等形式的Payloads

## 0x03 Precautions

- 当您首次使用本工具时，您需要运行如下命令换源:
```Bash
go env -w GO111MODULE=on
go env -w GOPROXY=https://goproxy.cn,direct
```

- 在使用本工具前，您只需下载[Golang](https://golang.google.cn/)作为运行环境

- 默认端口为**8083**，您可以在**main.go**中修改。

- 默认账户为`Adm1nstr@t0r`，密码为`Pr3c1se5!@#$%`，务必部署后在Settings处修改。

- 本工具隧道部分依赖Chisel，已放在tools目录中，不放心的师傅可以前往[Chisel Github仓库](https://github.com/jpillora/chisel)自行下载

## 0x04 Disclaimer

1. 您的下载、安装、使用或修改本工具及相关代码，意味着您对本工具的信任。
2. 本工具在使用过程中可能对您或他人造成损失或伤害，若发生此类情况，我们不承担任何责任。
3. 如果您因使用本工具而从事任何非法行为，您将自行承担一切后果，并且我们不承担任何法律责任或连带责任。
4. 请在使用前，仔细阅读并充分理解所有条款，特别是关于责任免除或限制的条款，并自行决定是否接受。
5. 除非您已经完全理解并接受所有条款，否则您无法下载、安装或使用本工具。
6. 您的任何下载、安装或使用行为，均视为您已完全阅读并同意本协议条款。
