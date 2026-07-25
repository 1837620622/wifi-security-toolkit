# macOS / Apple Silicon 专用

## 本目录做什么

在 **Apple Silicon + hashcat Metal** 上做离线 WPA 破解。  
字典与握手包**不放在本目录**，统一走仓库 **`../shared/`**。

```text
mac/
  crack.sh      ← 主入口
  monitor.sh    ← 看结果
  work/         ← 运行输出
shared/
  dicts/        ← 自动加载的字典
  captures/     ← 默认握手包
```

## 安装

```bash
brew install hashcat
hashcat -I    # 确认 Metal/Apple 设备
```

可选：安装 `hcxtools` 以便直接喂 `.cap`。

## 使用

```bash
# 握手包
cp ~/hs/*.hc22000 ../shared/captures/

cd /path/to/repo/mac
bash crack.sh

# 自定义
bash crack.sh --hash ~/a.hc22000
bash crack.sh --cap ~/hs.cap --dict-dir /Volumes/Data/dicts
bash crack.sh --capture-dir ~/handshakes
```

另开终端：

```bash
bash monitor.sh
```

## 硬件建议

优先 **Mac Studio Ultra/Max** 或 **16″ MacBook Pro Max**，统一内存 **≥64GB**。  
详见根 README「算力后端推荐」。不使用 Kaggle。
