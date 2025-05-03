import cv2
import numpy as np

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
    # Inverse matrix of Arnold Cat Map
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

# === ENCRYPT FUNCTION (For RGB Images) ===
def encrypt_image(image, a=1, b=1, iterations=10, x0=0.5, r=3.99):
    encrypted = np.zeros((image.shape[0], image.shape[1], 3), dtype=np.uint8)
    for c in range(3):  # Process R, G, B channels separately
        scrambled = cat_map(image[:, :, c], a, b, iterations)
        seq = logistic_map(x0, r, scrambled.size).reshape(scrambled.shape)
        encrypted[:, :, c] = scrambled ^ seq
    return encrypted

# === DECRYPT FUNCTION (For RGB Images) ===
def decrypt_image(encrypted_image, a=1, b=1, iterations=10, x0=0.5, r=3.99):
    decrypted = np.zeros((encrypted_image.shape[0], encrypted_image.shape[1], 3), dtype=np.uint8)
    for c in range(3):  # Process R, G, B channels separately
        seq = logistic_map(x0, r, encrypted_image[:, :, c].size).reshape(encrypted_image[:, :, c].shape)
        scrambled = encrypted_image[:, :, c] ^ seq
        decrypted[:, :, c] = inverse_cat_map(scrambled, a, b, iterations)
    return decrypted

# === MAIN PROGRAM ===
'''if __name__ == "__main__":
    # Load image in color (RGB)
    img = cv2.imread("us.jpg", cv2.IMREAD_COLOR)
    img = cv2.resize(img, (256, 256))  # Ensure square image

    # Parameters
    a, b = 1, 1
    iterations = 10
    x0 = 0.6
    r = 3.99

    # Encrypt and Decrypt
    encrypted = encrypt(img, a, b, iterations, x0, r)
    decrypted = decrypt(encrypted, a, b, iterations, x0, r)

    # Save results
    cv2.imwrite("encrypted.png", encrypted)
    cv2.imwrite("decrypted.png", decrypted)

    print("Encryption and decryption completed successfully.")'''


'''
img = cv2.imread(save_path, cv2.IMREAD_UNCHANGED)

if img is not None and len(img.shape) == 3 and img.shape[2] == 4:
    # Split channels
    b, g, r, a = cv2.split(img)

    # Create white background
    white_bg = np.ones_like(a) * 255

    # Alpha blending (composite over white)
    alpha = a.astype(float) / 255
    b = b * alpha + white_bg * (1 - alpha)
    g = g * alpha + white_bg * (1 - alpha)
    r = r * alpha + white_bg * (1 - alpha)

    # Merge back into BGR image
    img = cv2.merge([b.astype(np.uint8), g.astype(np.uint8), r.astype(np.uint8)])

img = cv2.resize(img, (420, 420))
'''

