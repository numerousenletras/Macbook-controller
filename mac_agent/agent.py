from __future__ import annotations

import asyncio
import base64
import io
import json
import os

import httpx
import mss
import pyautogui
import websockets
from PIL import Image
from dotenv import load_dotenv

load_dotenv()

RELAY_HTTP_URL = os.getenv("RELAY_HTTP_URL", "http://127.0.0.1:8787")
RELAY_WS_URL = os.getenv("RELAY_WS_URL", "ws://127.0.0.1:8787")
MAC_DEVICE_TOKEN = os.getenv("MAC_DEVICE_TOKEN", "change-me")
FRAME_INTERVAL_SECONDS = float(os.getenv("FRAME_INTERVAL_SECONDS", "0.45"))
JPEG_QUALITY = int(os.getenv("JPEG_QUALITY", "40"))
MAX_WIDTH = int(os.getenv("MAX_WIDTH", "1280"))

pyautogui.FAILSAFE = False


async def create_pair_code() -> str:
    headers = {"Authorization": f"Bearer {MAC_DEVICE_TOKEN}"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{RELAY_HTTP_URL}/api/codes", headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data["code"]


def capture_frame() -> dict[str, object]:
    with mss.mss() as sct:
        monitor = sct.monitors[1]
        shot = sct.grab(monitor)

    image = Image.frombytes("RGB", shot.size, shot.rgb)
    width, height = image.size
    if width > MAX_WIDTH:
        new_height = int(height * (MAX_WIDTH / width))
        image = image.resize((MAX_WIDTH, new_height), Image.Resampling.LANCZOS)

    buf = io.BytesIO()
    image.save(buf, format="JPEG", quality=JPEG_QUALITY)
    encoded = base64.b64encode(buf.getvalue()).decode("utf-8")

    return {
        "type": "frame",
        "width": image.width,
        "height": image.height,
        "image": f"data:image/jpeg;base64,{encoded}",
    }


def normalized_to_screen(x: float, y: float) -> tuple[int, int]:
    sw, sh = pyautogui.size()
    px = max(0, min(sw - 1, int(x * sw)))
    py = max(0, min(sh - 1, int(y * sh)))
    return px, py


def apply_event(event: dict[str, object]) -> None:
    event_type = str(event.get("type", ""))
    if event_type == "move":
        x, y = normalized_to_screen(float(event.get("x", 0.5)), float(event.get("y", 0.5)))
        pyautogui.moveTo(x, y, duration=0)
    elif event_type == "click":
        x, y = normalized_to_screen(float(event.get("x", 0.5)), float(event.get("y", 0.5)))
        button = str(event.get("button", "left"))
        pyautogui.click(x=x, y=y, button=button)
    elif event_type == "double_click":
        x, y = normalized_to_screen(float(event.get("x", 0.5)), float(event.get("y", 0.5)))
        pyautogui.doubleClick(x=x, y=y)
    elif event_type == "scroll":
        amount = int(event.get("amount", 0))
        pyautogui.scroll(amount)
    elif event_type == "key":
        key = str(event.get("key", ""))
        if key:
            pyautogui.press(key)
    elif event_type == "type_text":
        text = str(event.get("text", ""))
        if text:
            pyautogui.write(text, interval=0.01)


async def sender(ws: websockets.WebSocketClientProtocol) -> None:
    while True:
        await ws.send(json.dumps(capture_frame()))
        await asyncio.sleep(FRAME_INTERVAL_SECONDS)


async def receiver(ws: websockets.WebSocketClientProtocol) -> None:
    async for raw in ws:
        try:
            event = json.loads(raw)
            apply_event(event)
        except Exception as err:
            print(f"event_error={err}")


async def run() -> None:
    code = await create_pair_code()
    print("=" * 50)
    print(f"Pair this Mac from iPhone using code: {code}")
    print("Code expires in 5 minutes")
    print("=" * 50)

    ws_url = f"{RELAY_WS_URL}/ws/mac/{code}?token={MAC_DEVICE_TOKEN}"
    async with websockets.connect(ws_url, max_size=15_000_000) as ws:
        await asyncio.gather(sender(ws), receiver(ws))


if __name__ == "__main__":
    asyncio.run(run())
