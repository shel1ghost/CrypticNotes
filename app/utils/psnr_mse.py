import cv2
import numpy as np

def mse(image1, image2):
    """Calculate Mean Squared Error (MSE) between two images."""
    return np.mean((image1 - image2) ** 2)

def psnr(image1, image2):
    """Calculate Peak Signal-to-Noise Ratio (PSNR) between two images."""
    mse_value = mse(image1, image2)
    if mse_value == 0:  # No difference between images
        return float('inf')
    max_pixel = 255.0
    return 10 * np.log10((max_pixel ** 2) / mse_value)

