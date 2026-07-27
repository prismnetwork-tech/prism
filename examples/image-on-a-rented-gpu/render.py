import base64
import io
import os
import sys
import time

import torch
from diffusers import AutoPipelineForText2Image

PROMPT = os.environ.get("PRISM_PROMPT", "a glass prism splitting light on a black desk, studio photograph")
MODEL = os.environ.get("PRISM_MODEL", "stabilityai/sd-turbo")

if not torch.cuda.is_available():
    sys.exit("no CUDA device on this machine")

device = torch.cuda.get_device_name(0)
print(f"gpu: {device}", flush=True)

started = time.time()
pipeline = AutoPipelineForText2Image.from_pretrained(MODEL, torch_dtype=torch.float16, variant="fp16")
pipeline = pipeline.to("cuda")
print(f"weights ready in {time.time() - started:.1f}s", flush=True)

started = time.time()
# SD-Turbo is a distilled model: one step, and guidance off.
image = pipeline(prompt=PROMPT, num_inference_steps=1, guidance_scale=0.0).images[0]
print(f"rendered in {time.time() - started:.2f}s", flush=True)

buffer = io.BytesIO()
image.save(buffer, format="PNG")
# The image comes home in the command output, so the caller needs no second
# channel back to a machine that is about to be destroyed.
print("PRISM_IMAGE_BASE64:" + base64.b64encode(buffer.getvalue()).decode(), flush=True)
