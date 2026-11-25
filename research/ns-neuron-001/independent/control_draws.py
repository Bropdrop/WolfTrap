"""Seeded controls for the original 32-dimensional miniature transformer."""
import random

import numpy as np


def cpu_normal_16(seed, count):
    """Generate blocks of 16 Gaussian draws using the legacy CPU generator layout."""
    if count % 16:
        raise ValueError("This check implements only complete blocks of 16.")
    generator = np.random.RandomState(seed)
    words = generator.randint(0, 2**32, size=count, dtype=np.uint32)
    uniform = (words & 0xFFFFFF).astype(np.float32) * np.float32(2**-24)
    blocks = uniform.reshape(-1, 16)
    radii = np.sqrt(-2 * np.log(1 - blocks[:, :8]))
    angles = np.float32(2 * np.pi) * blocks[:, 8:]
    return np.column_stack((radii * np.cos(angles), radii * np.sin(angles))).ravel()


def generate_controls(layer_width, selected_neuron, amplitude, seed=17023):
    """Regenerate the six same-layer IDs and six equal-norm 32D fixture directions."""
    candidates = [i for i in range(layer_width) if i != selected_neuron]
    neuron_ids = random.Random(seed + 2).sample(candidates, 6)
    normals = cpu_normal_16(seed + 3, 6 * 32).reshape(6, 32)
    directions = normals / np.linalg.norm(normals, axis=1, keepdims=True)
    return neuron_ids, directions * np.float32(amplitude)
