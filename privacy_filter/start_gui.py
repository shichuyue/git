"""
隐私流量拦截代理 - 一键启动脚本
启动 Web 管理界面，自动打开浏览器。
"""
import sys
import os
import threading
import webbrowser

# 将项目目录加入 Python 路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from web_gui import app

WEB_PORT = 8090


def open_browser():
    """延迟 2 秒打开浏览器"""
    import time
    time.sleep(2)
    webbrowser.open(f"http://127.0.0.1:{WEB_PORT}")


if __name__ == "__main__":
    print("=" * 50)
    print("  隐私流量拦截代理 - Web 管理界面")
    print("=" * 50)
    print(f"  启动中...")
    print(f"  打开浏览器访问 http://127.0.0.1:{WEB_PORT}")
    print(f"  确保系统代理已设置为 127.0.0.1:8080")
    print(f"  按 Ctrl+C 停止")
    print("=" * 50)

    # 后台线程打开浏览器
    threading.Thread(target=open_browser, daemon=True).start()

    # 启动 Flask
    app.run(host="127.0.0.1", port=WEB_PORT, debug=False, threaded=True)
