import cv2
import numpy as np
import os

# === CHAOTIC FUNCTION (Logistic Map for diffusion) ===
def logistic_map(x, r, size):
    seq = []
    for _ in range(size):
        x = r * x * (1 - x)
        seq.append(int(x * 256) % 256)
    return np.array(seq, dtype=np.uint8)

# === ARNOLD CAT MAP TRANSFORMATION ===
def cat_map(channel, a, b, iterations):
    N = channel.shape[0]
    result = np.copy(channel)
    for _ in range(iterations):
        temp = np.zeros_like(result)
        for x in range(N):
            for y in range(N):
                x_new = (x + a * y) % N
                y_new = (b * x + (a * b + 1) * y) % N
                temp[x_new, y_new] = result[x, y]
        result = temp
    return result

# === INVERSE CAT MAP (Decryption) ===
def inverse_cat_map(channel, a, b, iterations):
    N = channel.shape[0]
    mat = np.array([[1, a], [b, a * b + 1]])
    det = int(np.round(np.linalg.det(mat)))
    inv_det = pow(det, -1, N)

    inv_mat = np.linalg.inv(mat) * det * inv_det
    inv_mat = inv_mat.astype(int) % N

    result = np.copy(channel)
    for _ in range(iterations):
        temp = np.zeros_like(result)
        for x in range(N):
            for y in range(N):
                x_new = (inv_mat[0, 0] * x + inv_mat[0, 1] * y) % N
                y_new = (inv_mat[1, 0] * x + inv_mat[1, 1] * y) % N
                temp[x_new, y_new] = result[x, y]
        result = temp
    return result

# === ENCRYPT FUNCTION (Modified to show phases) ===
def encryption_process(image, encrypted_filename, a=1, b=1, iterations=10, x0=0.5, r=3.99):
    encrypted = np.zeros_like(image)
    scrambled_image = np.zeros_like(image)
    diffused_image = np.zeros_like(image)
    
    for c in range(3):  # R, G, B
        scrambled = cat_map(image[:, :, c], a, b, iterations)
        seq = logistic_map(x0, r, scrambled.size).reshape(scrambled.shape)
        diffused = scrambled ^ seq

        encrypted[:, :, c] = diffused
        scrambled_image[:, :, c] = scrambled
        diffused_image[:, :, c] = diffused

    # Save phases
    phase1_save_path = os.path.join('app/static/uploads', f"phase1_{encrypted_filename}.png")
    phase2_save_path = os.path.join('app/static/uploads', f"phase2_{encrypted_filename}.png")
    cv2.imwrite(phase1_save_path, scrambled_image)
    cv2.imwrite(phase2_save_path, diffused_image)

    return encrypted

# === MAIN ===
'''if __name__ == "__main__":
    img = cv2.imread("hello.png", cv2.IMREAD_UNCHANGED)

    if img is not None and len(img.shape) == 3 and img.shape[2] == 4:
        b, g, r, a = cv2.split(img)
        white_bg = np.ones_like(a) * 255
        alpha = a.astype(float) / 255
        b = b * alpha + white_bg * (1 - alpha)
        g = g * alpha + white_bg * (1 - alpha)
        r = r * alpha + white_bg * (1 - alpha)
        img = cv2.merge([b.astype(np.uint8), g.astype(np.uint8), r.astype(np.uint8)])

    img = cv2.resize(img, (256, 256))

    a, b = 1, 1
    iterations = 10
    x0 = 0.6
    r = 3.99

    encrypted = encrypt(img, a, b, iterations, x0, r)
    decrypted = decrypt(encrypted, a, b, iterations, x0, r)

    cv2.imwrite("original.png", img)
    cv2.imwrite("encrypted.png", encrypted)
    cv2.imwrite("decrypted.png", decrypted)

    print("Phases saved: scrambled, diffused, dediffused, unscrambled.")'''
