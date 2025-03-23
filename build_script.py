import os
import sys
import subprocess
import shutil
from pathlib import Path

def create_icon():
    """Create a simple icon file using PIL."""
    from PIL import Image, ImageDraw
    
    # Create a 256x256 image with a transparent background
    size = 256
    image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    
    # Draw a shield shape
    points = [
        (size//2, 0),  # top
        (size, size//4),  # right top
        (size, size*3//4),  # right bottom
        (size//2, size),  # bottom
        (0, size*3//4),  # left bottom
        (0, size//4),  # left top
    ]
    
    # Draw the shield with a gradient
    for i in range(size//2):
        color = (0, 120 + i//2, 255 - i//2, 255)  # Blue gradient
        draw.polygon(points, fill=color)
        points = [(x-1, y) for x, y in points]
    
    # Save as ICO
    image.save('icon.ico', format='ICO')

def build_executable():
    """Build the executable using PyInstaller."""
    # Create icon if it doesn't exist
    if not os.path.exists('icon.ico'):
        create_icon()
    
    # Install required packages
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyinstaller'])
    
    # Build the executable
    subprocess.run([
        'pyinstaller',
        '--clean',
        '--noconfirm',
        '--onefile',
        '--windowed',
        '--icon=icon.ico',
        '--name=CybersecuritySystem',
        'gui.py'
    ])
    
    # Create distribution directory
    dist_dir = Path('dist')
    dist_dir.mkdir(exist_ok=True)
    
    # Copy executable to distribution directory
    shutil.copy2(
        'dist/CybersecuritySystem.exe',
        'dist/CybersecuritySystem.exe'
    )
    
    # Create a simple README for the distribution
    with open('dist/README.txt', 'w') as f:
        f.write("""AI-Driven Cybersecurity System

1. Double-click CybersecuritySystem.exe to run the application
2. Enter your system information in the GUI
3. Click "Analyze System" to start the analysis
4. View the results in the output window

Note: You need an OpenAI API key to use this application.
Create a .env file in the same directory with your API key:
OPENAI_API_KEY=your-api-key-here
""")
    
    print("Build complete! Executable is in the 'dist' directory.")

if __name__ == "__main__":
    build_executable() 