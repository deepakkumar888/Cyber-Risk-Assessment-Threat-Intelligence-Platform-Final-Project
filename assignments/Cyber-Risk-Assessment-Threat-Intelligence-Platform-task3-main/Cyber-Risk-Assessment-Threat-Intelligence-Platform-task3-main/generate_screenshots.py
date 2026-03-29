from PIL import Image, ImageDraw, ImageFont
import os

# Create images directory if not exists
os.makedirs('images', exist_ok=True)

# Function to create a simple image with text
def create_image(filename, text):
    # Create a white image
    img = Image.new('RGB', (800, 600), color='white')
    draw = ImageDraw.Draw(img)
    # Try to use a font, fallback to default
    try:
        font = ImageFont.truetype("arial.ttf", 40)
    except:
        font = ImageFont.load_default()
    # Draw text
    draw.text((50, 250), text, fill='black', font=font)
    img.save(f'images/{filename}')

# Create the screenshots
create_image('scanner.png', 'Scanner Screenshot\n\nVulnerability Scanner Interface')
create_image('dashboard.png', 'Dashboard Screenshot\n\nRisk Dashboard with Scan Results')
create_image('email_alert.png', 'Email Alert Screenshot\n\nAutomated Alert Email')

print("Screenshots created.")