import os
from PIL import Image

END_MARKER = "####END####"
IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".bmp", ".webp")


def list_images():
    images = [
        f for f in os.listdir(".")
        if f.lower().endswith(IMAGE_EXTENSIONS)
    ]

    if not images:
        print("\n[-] No image files found.")
        return []

    print("\nAvailable Images")
    print("-" * 60)

    for i, img in enumerate(images, 1):
        try:
            image = Image.open(img)
            width, height = image.size
            size_kb = os.path.getsize(img) / 1024

            print(
                f"{i}. {img} | "
                f"{width}x{height} | "
                f"{size_kb:.1f} KB"
            )

        except Exception:
            print(f"{i}. {img}")

    return images


def select_image():
    images = list_images()

    if not images:
        return None

    try:
        choice = int(input("\nSelect image number: "))
        return images[choice - 1]

    except (ValueError, IndexError):
        print("[-] Invalid selection")
        return None


def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)


def binary_to_text(binary):
    chars = []

    for i in range(0, len(binary), 8):
        byte = binary[i:i + 8]

        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))

    return ''.join(chars)


def encode_image(image_path, message):
    try:
        img = Image.open(image_path).convert("RGB")
        pixels = img.load()

        message += END_MARKER
        binary_message = text_to_binary(message)

        max_capacity = img.width * img.height * 3

        if len(binary_message) > max_capacity:
            print("[-] Message too large for image.")
            return

        index = 0

        for y in range(img.height):
            for x in range(img.width):

                r, g, b = pixels[x, y]

                if index < len(binary_message):
                    r = (r & ~1) | int(binary_message[index])
                    index += 1

                if index < len(binary_message):
                    g = (g & ~1) | int(binary_message[index])
                    index += 1

                if index < len(binary_message):
                    b = (b & ~1) | int(binary_message[index])
                    index += 1

                pixels[x, y] = (r, g, b)

                if index >= len(binary_message):
                    base = os.path.splitext(image_path)[0]
                    output_file = f"{base}_encoded.png"

                    img.save(output_file)

                    print("\n[+] Message encoded successfully")
                    print(f"[+] Saved as: {output_file}")
                    return

    except Exception as e:
        print(f"[-] Error: {e}")


def decode_image(image_path):
    try:
        img = Image.open(image_path).convert("RGB")
        pixels = img.load()

        binary_data = ""

        for y in range(img.height):
            for x in range(img.width):

                r, g, b = pixels[x, y]

                binary_data += str(r & 1)
                binary_data += str(g & 1)
                binary_data += str(b & 1)

        text = binary_to_text(binary_data)

        if END_MARKER in text:
            hidden = text.split(END_MARKER)[0]

            print("\nHidden Message")
            print("-" * 60)
            print(hidden)
        else:
            print("[-] No hidden message found.")

    except Exception as e:
        print(f"[-] Error: {e}")


def show_capacity(image_path):
    try:
        img = Image.open(image_path)

        bits = img.width * img.height * 3
        chars = bits // 8

        print(f"\nCapacity: ~{chars:,} characters")

    except Exception:
        pass


def main():

    while True:

        print("\n" + "=" * 60)
        print("Image Steganography Tool")
        print("=" * 60)

        print("1. List Images")
        print("2. Encode Message")
        print("3. Decode Message")
        print("4. Exit")

        choice = input("\nChoice: ").strip()

        if choice == "1":

            list_images()

        elif choice == "2":

            image = select_image()

            if image:
                show_capacity(image)

                message = input("\nEnter secret message:\n")

                encode_image(image, message)

        elif choice == "3":

            image = select_image()

            if image:
                decode_image(image)

        elif choice == "4":

            print("\nGoodbye.")
            break

        else:
            print("[-] Invalid option")


if __name__ == "__main__":
    main()