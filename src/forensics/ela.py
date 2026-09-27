"""
src/forensics/ela.py
Error Level Analysis (ELA) Engine for InternKavach
Detects image tampering by analyzing re-compression artifacts.
"""
from __future__ import annotations

import io
import tempfile
import os
from typing import Tuple

import numpy as np
from PIL import Image, ImageEnhance, ImageFilter


def generate_ela_heatmap(
    image_input,
    quality: int = 90,
    scale: int = 15,
) -> Tuple[Image.Image, float]:
    """
    Perform Error Level Analysis on an image.

    Args:
        image_input: File path (str) or bytes of the image.
        quality:     JPEG re-compression quality (default 90).
        scale:       Amplification factor for the error delta (default 15).

    Returns:
        (heatmap_image, tampering_probability)
        - heatmap_image: PIL.Image in RGB, colour-coded ELA difference map.
        - tampering_probability: float 0.0–1.0 estimated probability of tampering.
    """
    # ── Load original ─────────────────────────────────────────────────────────
    if isinstance(image_input, (str, os.PathLike)):
        original = Image.open(image_input).convert("RGB")
    elif isinstance(image_input, bytes):
        original = Image.open(io.BytesIO(image_input)).convert("RGB")
    elif isinstance(image_input, Image.Image):
        original = image_input.convert("RGB")
    else:
        raise TypeError(f"Unsupported image_input type: {type(image_input)}")

    # ── Re-compress at target quality ─────────────────────────────────────────
    buffer = io.BytesIO()
    original.save(buffer, format="JPEG", quality=quality)
    buffer.seek(0)
    recompressed = Image.open(buffer).convert("RGB")

    # ── Compute per-pixel absolute difference ─────────────────────────────────
    orig_arr = np.array(original, dtype=np.float32)
    recomp_arr = np.array(recompressed, dtype=np.float32)
    diff = np.abs(orig_arr - recomp_arr)

    # ── Amplify & normalise ───────────────────────────────────────────────────
    amplified = np.clip(diff * scale, 0, 255).astype(np.uint8)

    # ── Build RGB heat-map (low=blue, mid=green, high=red) ────────────────────
    gray = amplified.mean(axis=2)                    # (H, W) mean error
    norm = gray / (gray.max() + 1e-6)               # 0–1 normalised

    heatmap_rgb = np.zeros((*gray.shape, 3), dtype=np.uint8)
    # Blue channel → low error regions
    heatmap_rgb[:, :, 2] = ((1.0 - norm) * 255).astype(np.uint8)
    # Green channel → mid error
    heatmap_rgb[:, :, 1] = (np.sin(norm * np.pi) * 255).astype(np.uint8)
    # Red channel → high error (potential tampering)
    heatmap_rgb[:, :, 0] = (norm * 255).astype(np.uint8)

    heatmap_img = Image.fromarray(heatmap_rgb, "RGB")

    # Slight gaussian blur for visual clarity
    heatmap_img = heatmap_img.filter(ImageFilter.GaussianBlur(radius=1))

    # ── Compute tampering probability ─────────────────────────────────────────
    # Genuine unedited images have uniformly low ELA values.
    # Spliced/edited regions show localised high-variance spikes.
    flat = diff.reshape(-1, 3).mean(axis=1)           # per-pixel mean error
    mean_err = float(flat.mean())
    std_err = float(flat.std())

    # Heuristic: genuine images have mean ELA < 5 at quality=90.
    # Each unit above 5 adds ~3 % probability; high variance adds more.
    prob = min(1.0, (mean_err / 5.0) * 0.30 + (std_err / 10.0) * 0.40)
    # Boost if very bright hot-spots exist (99th percentile)
    p99 = float(np.percentile(flat, 99))
    if p99 > 50:
        prob = min(1.0, prob + 0.25)
    if p99 > 100:
        prob = min(1.0, prob + 0.20)

    return heatmap_img, round(prob, 4)


def ela_stats(image_input) -> dict:
    """Return raw ELA statistics without building the full heatmap."""
    if isinstance(image_input, (str, os.PathLike)):
        original = Image.open(image_input).convert("RGB")
    elif isinstance(image_input, bytes):
        original = Image.open(io.BytesIO(image_input)).convert("RGB")
    else:
        original = image_input.convert("RGB")

    buffer = io.BytesIO()
    original.save(buffer, format="JPEG", quality=90)
    buffer.seek(0)
    recompressed = Image.open(buffer).convert("RGB")

    diff = np.abs(
        np.array(original, dtype=np.float32) - np.array(recompressed, dtype=np.float32)
    )
    flat = diff.reshape(-1, 3).mean(axis=1)

    return {
        "mean_error": float(flat.mean()),
        "std_error": float(flat.std()),
        "p99_error": float(np.percentile(flat, 99)),
        "max_error": float(flat.max()),
    }
